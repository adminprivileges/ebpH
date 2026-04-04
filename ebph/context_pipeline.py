import hashlib
import json
import os
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

from ebph.ollama_client import OllamaAdjudicatorClient, OllamaAdjudicatorError


@dataclass
class SessionMetadata:
    session_id: str
    started_ts_ns: int
    scope_mode: int
    context_enabled: bool
    scope_baseline_mature: bool
    t_candidate: float
    t_high: float
    c_downgrade: float
    adjudicator_backend: str
    adjudicator_model_enabled: bool
    ollama_model: str
    ollama_base_url: str


class ContextPipeline:
    """
    Userspace stage-one/ stage-two decision support and replay writer.
    """

    SCHEMA_VERSION = 1
    BENIGN_DOWNGRADE_WHITELIST = {
        'benign_low_density',
    }

    def __init__(
        self,
        replay_root: str,
        scope_mode: int,
        context_enabled: bool,
        scope_baseline_mature: bool,
        t_candidate: float,
        t_high: float,
        c_downgrade: float,
        profile_summary_window: int,
        adjudicator_backend: str = 'stub',
        adjudicator_model_enabled: bool = False,
        ollama_base_url: str = 'http://127.0.0.1:11434',
        ollama_model: str = 'tinyllama:1.1b',
        ollama_timeout_sec: float = 1.0,
        ollama_keep_alive: str = '5m',
    ) -> None:
        self.scope_mode = scope_mode
        self.context_enabled = context_enabled
        self.scope_baseline_mature = scope_baseline_mature
        self.t_candidate = t_candidate
        self.t_high = t_high
        self.c_downgrade = c_downgrade
        self.adjudicator_backend = adjudicator_backend
        self.adjudicator_model_enabled = adjudicator_model_enabled
        self.ollama_client: Optional[OllamaAdjudicatorClient] = None
        if self.context_enabled and self.adjudicator_model_enabled and self.adjudicator_backend == 'ollama':
            self.ollama_client = OllamaAdjudicatorClient(
                base_url=ollama_base_url,
                model=ollama_model,
                timeout_sec=ollama_timeout_sec,
                keep_alive=ollama_keep_alive,
            )

        now_ns = time.time_ns()
        self.session_id = f'session-{now_ns}'
        self.session_dir = os.path.join(replay_root, self.session_id)
        os.makedirs(self.session_dir, exist_ok=True)

        self.case_log_path = os.path.join(self.session_dir, 'cases.jsonl')
        self.session_metadata_path = os.path.join(self.session_dir, 'session.json')

        self.profile_summary_window = profile_summary_window
        self.profile_history: Dict[Tuple[int, int], Deque[Dict[str, float]]] = defaultdict(
            lambda: deque(maxlen=self.profile_summary_window)
        )

        self._write_session_metadata(
            SessionMetadata(
                session_id=self.session_id,
                started_ts_ns=now_ns,
                scope_mode=scope_mode,
                context_enabled=context_enabled,
                scope_baseline_mature=scope_baseline_mature,
                t_candidate=t_candidate,
                t_high=t_high,
                c_downgrade=c_downgrade,
                adjudicator_backend=adjudicator_backend,
                adjudicator_model_enabled=adjudicator_model_enabled,
                ollama_model=ollama_model,
                ollama_base_url=ollama_base_url,
            )
        )

    def _write_session_metadata(self, metadata: SessionMetadata) -> None:
        with open(self.session_metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata.__dict__, f, sort_keys=True)

    def make_case_id(self, key_fields: List[Any]) -> str:
        raw = '|'.join(str(v) for v in key_fields)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    @staticmethod
    def _is_normal_from_status(profile_status: int) -> bool:
        return bool(profile_status & 0x4)

    def profile_summary_snapshot(self, scope_id: int, executable_key: int) -> Dict[str, float]:
        h = self.profile_history[(scope_id, executable_key)]
        if not h:
            return {
                'recent_case_count': 0,
                'recent_avg_stage1_score': 0.0,
                'recent_anomaly_density': 0.0,
                'recent_volatility': 0.0,
            }

        scores = [x['stage1_score'] for x in h]
        densities = [x['anomaly_density'] for x in h]
        volatility = statistics.pstdev(scores) if len(scores) > 1 else 0.0

        return {
            'recent_case_count': float(len(h)),
            'recent_avg_stage1_score': float(sum(scores) / len(scores)),
            'recent_anomaly_density': float(sum(densities) / len(densities)),
            'recent_volatility': float(volatility),
        }

    def update_profile_summary(
        self,
        scope_id: int,
        executable_key: int,
        stage1_score: float,
        anomaly_density: float,
    ) -> None:
        self.profile_history[(scope_id, executable_key)].append(
            {
                'stage1_score': float(stage1_score),
                'anomaly_density': float(anomaly_density),
            }
        )

    def compute_stage1_score(self, features: Dict[str, float]) -> float:
        score = (
            features.get('anomaly_events', 0.0) * 0.35 +
            features.get('anomaly_miss_sum', 0.0) * 0.20 +
            features.get('anomaly_miss_max', 0.0) * 0.15 +
            features.get('distinct_lsm_anomalies', 0.0) * 0.10 +
            features.get('anomaly_density', 0.0) * 1.20 +
            features.get('total_lfc_at_close', 0.0) * 0.02 +
            features.get('max_lfc_at_close', 0.0) * 0.04
        )
        return float(round(score, 6))

    def assign_band(self, score: float) -> str:
        if score < self.t_candidate:
            return 'low'
        if score < self.t_high:
            return 'candidate'
        return 'high'

    def adjudicate_stub(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        features = candidate['raw_stage1_features']
        density = float(features.get('anomaly_density', 0.0))
        miss_max = float(features.get('anomaly_miss_max', 0.0))

        if density < 0.15 and miss_max <= 1:
            return {
                'decision': 'not_detected',
                'confidence': 0.90,
                'reason_code': 'benign_low_density',
                'error': False,
            }

        return {
            'decision': 'detected',
            'confidence': 0.80,
            'reason_code': 'suspicious_pattern',
            'error': False,
        }

    def _run_adjudicator(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        if self.ollama_client is None:
            return self.adjudicate_stub(candidate)

        out = self.ollama_client.adjudicate(candidate)
        return {
            'decision': 'detected' if out['detected'] else 'not_detected',
            'confidence': float(out['confidence']),
            'reason_code': out['reason_code'],
            'rationale': out['rationale'],
            'error': False,
        }

    def finalize_decision(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        band = candidate['routing']['band']
        adjudicator_called = False
        adjudicator_ms = 0.0
        adjudicator_result = 'skipped'
        adjudicator_confidence = 0.0
        reason_code = 'none'
        downgrade_applied = False
        adjudicator_backend = self.adjudicator_backend if self.ollama_client is not None else 'stub'
        adjudicator_error = ''

        if band == 'low':
            final = 'not_detected'
        elif band == 'candidate':
            if not self.context_enabled:
                final = 'not_detected'
                reason_code = 'context_disabled_band2_default'
            else:
                adjudicator_called = True
                t0 = time.time_ns()
                try:
                    adj = self._run_adjudicator(candidate)
                    adjudicator_result = adj['decision']
                    adjudicator_confidence = float(adj['confidence'])
                    reason_code = adj['reason_code']
                    final = adj['decision']
                except (OllamaAdjudicatorError, Exception) as e:
                    adjudicator_result = 'error'
                    reason_code = 'adjudicator_error_band2_default'
                    final = 'not_detected'
                    adjudicator_error = str(e)
                adjudicator_ms = (time.time_ns() - t0) / 1e6
        else:
            final = 'detected'
            if self.context_enabled:
                adjudicator_called = True
                t0 = time.time_ns()
                try:
                    adj = self._run_adjudicator(candidate)
                    adjudicator_result = adj['decision']
                    adjudicator_confidence = float(adj['confidence'])
                    reason_code = adj['reason_code']
                    if (
                        adj['decision'] == 'not_detected' and
                        adjudicator_confidence >= self.c_downgrade and
                        reason_code in self.BENIGN_DOWNGRADE_WHITELIST
                    ):
                        final = 'not_detected'
                        downgrade_applied = True
                except (OllamaAdjudicatorError, Exception) as e:
                    adjudicator_result = 'error'
                    reason_code = 'adjudicator_error_band3_default'
                    final = 'detected'
                    adjudicator_error = str(e)
                adjudicator_ms = (time.time_ns() - t0) / 1e6

        candidate['decision'].update(
            {
                'adjudicator_called': adjudicator_called,
                'adjudicator_backend': adjudicator_backend,
                'adjudicator_result': adjudicator_result,
                'adjudicator_confidence': adjudicator_confidence,
                'reason_code': reason_code,
                'adjudicator_error': adjudicator_error,
                'downgrade_applied': downgrade_applied,
                'final_binary_decision': final,
            }
        )
        candidate['latency']['adjudicator_ms'] = float(round(adjudicator_ms, 3))
        return candidate

    def write_case(self, case: Dict[str, Any]) -> None:
        case.setdefault('replay', {})
        case['replay'].update(
            {
                'schema_version': self.SCHEMA_VERSION,
                'session_id': self.session_id,
                'recorded_ts_ns': time.time_ns(),
                'replayable': True,
            }
        )
        with open(self.case_log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(case, sort_keys=True) + '\n')
