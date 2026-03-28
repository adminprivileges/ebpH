import json
import urllib.error
import urllib.request
from typing import Any, Dict


class OllamaAdjudicatorError(Exception):
    pass


class OllamaAdjudicatorClient:
    RESPONSE_SCHEMA: Dict[str, Any] = {
        'type': 'object',
        'properties': {
            'detected': {'type': 'boolean'},
            'confidence': {'type': 'number'},
            'reason_code': {'type': 'string'},
            'rationale': {'type': 'string'},
        },
        'required': ['detected', 'confidence', 'reason_code', 'rationale'],
    }

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_sec: float,
        keep_alive: str,
    ) -> None:
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout_sec = timeout_sec
        self.keep_alive = keep_alive

    def _build_compact_payload(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        process = candidate.get('process', {})
        scope_profile = candidate.get('scope_profile', {})
        routing = candidate.get('routing', {})
        return {
            'case_id': candidate.get('case_id'),
            'stage1_score': candidate.get('decision', {}).get('stage1_score', 0.0),
            'band': routing.get('band', 'candidate'),
            'process': {
                'pid': process.get('pid', 0),
                'tid': process.get('tid', 0),
                'exe': process.get('exe', '[unknown]'),
                'executable_key': process.get('executable_key', 0),
            },
            'scope_profile': {
                'scope_id': scope_profile.get('scope_id', 0),
                'profile_key': scope_profile.get('profile_key', 0),
                'scope_baseline_mature': candidate.get('experiment', {}).get('scope_baseline_mature', False),
                'profile_seen_before': scope_profile.get('profile_seen_before', False),
                'profile_is_normal_at_open': scope_profile.get('profile_is_normal_at_open', False),
                'profile_is_normal_at_close': scope_profile.get('profile_is_normal_at_close', False),
            },
            'raw_stage1_features': candidate.get('raw_stage1_features', {}),
            'profile_window_summary': candidate.get('profile_window_summary', {}),
        }

    def _normalize_response(self, response_obj: Dict[str, Any]) -> Dict[str, Any]:
        missing = [k for k in self.RESPONSE_SCHEMA['required'] if k not in response_obj]
        if missing:
            raise OllamaAdjudicatorError(f'missing_fields: {",".join(missing)}')

        detected = response_obj['detected']
        confidence = response_obj['confidence']
        reason_code = response_obj['reason_code']
        rationale = response_obj['rationale']

        if not isinstance(detected, bool):
            raise OllamaAdjudicatorError('invalid_detected_type')
        if not isinstance(confidence, (float, int)):
            raise OllamaAdjudicatorError('invalid_confidence_type')
        if not isinstance(reason_code, str):
            raise OllamaAdjudicatorError('invalid_reason_code_type')
        if not isinstance(rationale, str):
            raise OllamaAdjudicatorError('invalid_rationale_type')

        confidence_norm = float(confidence)
        if confidence_norm < 0.0:
            confidence_norm = 0.0
        elif confidence_norm > 1.0:
            confidence_norm = 1.0

        return {
            'detected': detected,
            'confidence': confidence_norm,
            'reason_code': reason_code.strip() or 'unspecified',
            'rationale': rationale.strip()[:240],
        }

    def adjudicate(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        prompt_payload = self._build_compact_payload(candidate)
        body = {
            'model': self.model,
            'stream': False,
            'keep_alive': self.keep_alive,
            'format': self.RESPONSE_SCHEMA,
            'messages': [
                {
                    'role': 'system',
                    'content': (
                        'You are a deterministic security adjudicator. '
                        'Output JSON only, matching the schema exactly. '
                        'Keep rationale short and concrete.'
                    ),
                },
                {
                    'role': 'user',
                    'content': json.dumps(prompt_payload, separators=(',', ':')),
                },
            ],
        }

        req = urllib.request.Request(
            url=f'{self.base_url}/api/chat',
            data=json.dumps(body).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                raw = resp.read()
        except urllib.error.URLError as e:
            raise OllamaAdjudicatorError(f'http_error:{e.__class__.__name__}') from e
        except TimeoutError as e:
            raise OllamaAdjudicatorError('timeout') from e
        except Exception as e:
            raise OllamaAdjudicatorError(f'request_failed:{e.__class__.__name__}') from e

        try:
            outer = json.loads(raw.decode('utf-8'))
        except Exception as e:
            raise OllamaAdjudicatorError('invalid_outer_json') from e

        message = outer.get('message', {})
        content = message.get('content')
        if not isinstance(content, str):
            raise OllamaAdjudicatorError('invalid_message_content')

        try:
            parsed = json.loads(content)
        except Exception as e:
            raise OllamaAdjudicatorError('invalid_model_json') from e

        return self._normalize_response(parsed)
