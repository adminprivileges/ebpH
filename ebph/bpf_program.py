"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    A wrapper around the BPF program. Exposes methods for interacting
    with it from userspace and for handling events.

    2020-Jul-13  William Findlay  Created this.
"""

import os
import sys
import time
import atexit
import ctypes as ct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from bcc import BPF
from ratelimit import limits

from ebph.libebph import Lib
from ebph.logger import get_logger
from ebph.utils import running_processes, list_container_scope_ids
from ebph.structs import (
    EBPHProfileStruct,
    EBPH_SETTINGS,
    calculate_profile_magic,
    EBPH_LSM,
)
from ebph import defs
from ebph.context_pipeline import ContextPipeline

logger = get_logger()


def ringbuf_callback(bpf: BPF, map_name: str, infer_type: bool = True, ratelimit_per_sec = 9999999999):
    """
    Decorator that wraps a function in all of the logic
    to associate it with a ringbuffer @map_name in BPF land.

    If @infer_type is set, automatically get @bpf to cast
    event data to the correct structure. Pretty neat!

    TODO: Consider upstreaming this in bcc
    """
    def _inner(func):
        @limits(calls=ratelimit_per_sec, period=1, raise_on_limit=False)
        def _wrapper(ctx, data, size):
            if infer_type:
                data = bpf[map_name].event(data)
            func(ctx, data, size)

        bpf[map_name].open_ring_buffer(_wrapper)

    return _inner


class BPFProgram:
    """
    Wraps the BPF program and exposes methods for interacting with it.
    """
    def __init__(self, debug: bool = False, log_sequences: bool = False,
                 auto_save = True, auto_load = True,
                 scope_mode: int = defs.SCOPE_MODE_HOST,
                 bootstrap_mode: str = 'auto',
                 context_enabled: bool = False,
                 scope_baseline_mature: bool = True,
                 window_inactivity_timeout: float = defs.WINDOW_INACTIVITY_TIMEOUT_SEC,
                 window_hard_max: float = defs.WINDOW_HARD_MAX_SEC,
                 stage1_t_candidate: float = defs.STAGE1_T_CANDIDATE,
                 stage1_t_high: float = defs.STAGE1_T_HIGH,
                 stage2_c_downgrade: float = defs.STAGE2_C_DOWNGRADE):
        self.bpf = None
        self.usdt_contexts = []
        self.seqstack_inner_bpf = None
        self.cflags = []

        # Number of elapsed ticks
        self.tick_count = 0

        self.debug = debug
        self.auto_save = auto_save
        self.auto_load = auto_load
        self.scope_mode = scope_mode
        self.bootstrap_mode = bootstrap_mode
        self.context_enabled = context_enabled
        self.scope_baseline_mature = scope_baseline_mature
        self.window_inactivity_timeout = window_inactivity_timeout
        self.window_hard_max = window_hard_max
        self.stage1_t_candidate = stage1_t_candidate
        self.stage1_t_high = stage1_t_high
        self.stage2_c_downgrade = stage2_c_downgrade

        self.profile_key_to_exe = defaultdict(lambda: '[unknown]')
        self.syscall_number_to_name = defaultdict(lambda: '[unknown]')
        self.process_windows: Dict[Tuple[int, int, int], Dict[str, Any]] = {}
        self.tgid_resolution_fallback_count = 0
        self.context_pipeline = ContextPipeline(
            replay_root=defs.REPLAY_ROOT_DIR,
            scope_mode=self.scope_mode,
            context_enabled=self.context_enabled,
            scope_baseline_mature=self.scope_baseline_mature,
            t_candidate=self.stage1_t_candidate,
            t_high=self.stage1_t_high,
            c_downgrade=self.stage2_c_downgrade,
            profile_summary_window=defs.PROFILE_SUMMARY_WINDOW,
        )

        self._set_cflags()
        try:
            self._load_bpf()
        except Exception as e:
            logger.error('Unable to load BPF program', exc_info=e)
            sys.exit(1)
        try:
            self._register_ring_buffers()
        except Exception as e:
            logger.error('Unable to register ring buffers', exc_info=e)
            sys.exit(1)
        if self.auto_load:
            self.load_profiles()

        atexit.register(self._cleanup)

        if log_sequences:
            self.change_setting(EBPH_SETTINGS.LOG_SEQUENCES, log_sequences)

        if defs.ENFORCING:
            self.change_setting(EBPH_SETTINGS.ENFORCING, defs.ENFORCING)

        self.change_setting(EBPH_SETTINGS.NORMAL_WAIT, defs.NORMAL_WAIT)
        self.change_setting(EBPH_SETTINGS.NORMAL_FACTOR, defs.NORMAL_FACTOR)
        self.change_setting(EBPH_SETTINGS.NORMAL_FACTOR_DEN, defs.NORMAL_FACTOR_DEN)
        self.change_setting(EBPH_SETTINGS.ANOMALY_LIMIT, defs.ANOMALY_LIMIT)
        self.change_setting(EBPH_SETTINGS.TOLERIZE_LIMIT, defs.TOLERIZE_LIMIT)

        self._sync_container_scope_ids()
        try:
            self._bootstrap_processes()
        except Exception as e:
            logger.error('Unable to bootstrap processes', exc_info=e)

        self.start_monitoring()

    def on_tick(self) -> None:
        """
        Perform this operation every time ebphd ticks.
        """
        try:
            self.tick_count += 1

            if self.auto_save and self.tick_count % defs.PROFILE_SAVE_INTERVAL == 0:
                self.save_profiles()

            if self.tick_count % 10 == 0:
                self._sync_container_scope_ids()

            self.bpf.ring_buffer_consume()
            self._process_window_tick()
        except Exception as e:
            logger.error('Tick failed', exc_info=e)

    def _resolve_process_identity(self, tid: int) -> Tuple[int, bool]:
        try:
            tgid = int(self.get_process(tid).tgid)
            return tgid, False
        except Exception:
            pass

        # Best effort procfs fallback for short-lived processes whose task_state
        # has already been cleaned up by the time the userspace callback runs.
        try:
            with open(f'/proc/{tid}/status', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('Tgid:'):
                        tgid = int(line.split(':', 1)[1].strip())
                        if tgid > 0:
                            return tgid, False
                        break
        except Exception:
            pass

        self.tgid_resolution_fallback_count += 1
        # This can be noisy for very short-lived processes, so keep it to debug.
        logger.debug(
            f'TGID resolution failed for tid={tid}; using TID-based fallback windowing '
            f'(fallback_count={self.tgid_resolution_fallback_count}).'
        )
        return tid, True

    @staticmethod
    def _is_normal_profile_status(status: int) -> bool:
        return bool(status & 0x4)

    def _build_window_key(self, scope_id: int, profile_key: int, process_id: int) -> Tuple[int, int, int]:
        return (int(scope_id), int(profile_key), int(process_id))

    def _get_or_open_window(self, event) -> Dict[str, Any]:
        now_ns = time.time_ns()
        tid = int(event.pid)
        process_id, tid_fallback = self._resolve_process_identity(tid)
        key = self._build_window_key(event.scope_id, event.profile_key, process_id)

        window = self.process_windows.get(key)
        if window is not None:
            return window

        profile_exists_at_open = True
        profile_is_normal_at_open = False
        executable_key = int(event.profile_key)
        try:
            profile = self.get_profile(event.profile_key)
            profile_is_normal_at_open = self._is_normal_profile_status(profile.status)
        except Exception:
            profile_exists_at_open = False

        try:
            executable_key = int(self.get_profile_executable_key(event.profile_key))
        except Exception:
            executable_key = int(event.profile_key)

        window = {
            'scope_id': int(event.scope_id),
            'profile_key': int(event.profile_key),
            'process_id': int(process_id),
            'trigger_tid': tid,
            'last_trigger_tid': tid,
            'tid_fallback_used': bool(tid_fallback),
            'open_ts_ns': now_ns,
            'last_anomaly_ts_ns': now_ns,
            'trigger_tids': {tid},
            'anomaly_events': 0,
            'anomaly_miss_sum': 0,
            'anomaly_miss_max': 0,
            'distinct_lsm_anomalies': set(),
            'task_count_first': int(event.task_count),
            'task_count_last': int(event.task_count),
            'tolerize_limit_hits': 0,
            'new_sequence_events': 0,
            'normal_start_events': 0,
            'normal_stop_events': 0,
            'profile_exists_at_open': profile_exists_at_open,
            'profile_seen_before': profile_exists_at_open,
            'profile_is_normal_at_open': profile_is_normal_at_open,
            'executable_key': executable_key,
        }
        self.process_windows[key] = window
        return window

    def _process_window_tick(self) -> None:
        now_ns = time.time_ns()
        close_keys: List[Tuple[int, int, int]] = []
        close_reasons: Dict[Tuple[int, int, int], str] = {}

        for key, window in self.process_windows.items():
            inactive_sec = (now_ns - window['last_anomaly_ts_ns']) / 1e9
            duration_sec = (now_ns - window['open_ts_ns']) / 1e9
            if inactive_sec >= self.window_inactivity_timeout:
                close_keys.append(key)
                close_reasons[key] = 'inactivity_timeout'
                continue
            if duration_sec >= self.window_hard_max:
                close_keys.append(key)
                close_reasons[key] = 'hard_max_duration'
                continue

            live = False
            for tid in window['trigger_tids']:
                try:
                    _ = self.get_process(int(tid))
                    live = True
                    break
                except Exception:
                    continue
            if not live:
                close_keys.append(key)
                close_reasons[key] = 'process_exit'

        for key in close_keys:
            window = self.process_windows.pop(key, None)
            if window:
                self._finalize_window(window, close_reasons[key], now_ns)

    def _enrich_open_window(self, scope_id: int, profile_key: int, tid: int, field: str, value: int = 1) -> None:
        process_id, _ = self._resolve_process_identity(tid)
        key = self._build_window_key(scope_id, profile_key, process_id)
        window = self.process_windows.get(key)
        if not window:
            return
        window[field] = window.get(field, 0) + value

    def _finalize_window(self, window: Dict[str, Any], close_reason: str, close_ts_ns: int) -> None:
        t0_ns = time.time_ns()
        scope_id = int(window['scope_id'])
        profile_key = int(window['profile_key'])
        process_id = int(window['process_id'])
        trigger_tid = int(window['trigger_tid'])
        last_trigger_tid = int(window['last_trigger_tid'])

        pid = process_id
        tid = last_trigger_tid
        ppid = 0
        count = window['task_count_last']
        total_lfc = 0
        max_lfc = 0

        try:
            p = self.get_process(last_trigger_tid)
            pid = int(p.tgid)
            tid = int(p.pid)
            count = int(p.count)
            total_lfc = int(p.total_lfc)
            max_lfc = int(p.max_lfc)
            try:
                with open(f'/proc/{pid}/status', 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('PPid:'):
                            ppid = int(line.split(':', 1)[1].strip())
                            break
            except Exception:
                ppid = 0
        except Exception:
            pass

        exe = self.profile_key_to_exe[profile_key]
        executable_key = int(window['executable_key'])

        profile_status = 0
        profile_anomaly_count = 0
        train_count = 0
        last_mod_count = 0
        profile_count = 0
        sequences = 0
        normal_time_ns = 0

        try:
            profile = self.get_profile(profile_key)
            profile_status = int(profile.status)
            profile_anomaly_count = int(profile.anomaly_count)
            train_count = int(profile.train_count)
            last_mod_count = int(profile.last_mod_count)
            profile_count = int(profile.count)
            sequences = int(profile.sequences)
            normal_time_ns = int(profile.normal_time)
        except Exception:
            pass

        duration_ms = (close_ts_ns - window['open_ts_ns']) / 1e6
        task_count_delta = max(0, int(window['task_count_last']) - int(window['task_count_first']))
        anomaly_density = float(window['anomaly_events']) / max(1.0, duration_ms / 1000.0)

        raw_features = {
            'anomaly_events': float(window['anomaly_events']),
            'anomaly_miss_sum': float(window['anomaly_miss_sum']),
            'anomaly_miss_max': float(window['anomaly_miss_max']),
            'distinct_lsm_anomalies': float(len(window['distinct_lsm_anomalies'])),
            'task_count_at_first_anomaly': float(window['task_count_first']),
            'task_count_at_last_anomaly': float(window['task_count_last']),
            'task_count_delta': float(task_count_delta),
            'total_lfc_at_close': float(total_lfc),
            'max_lfc_at_close': float(max_lfc),
            'tolerize_limit_hits': float(window['tolerize_limit_hits']),
            'new_sequence_events': float(window['new_sequence_events']),
            'normal_start_events_in_window': float(window['normal_start_events']),
            'normal_stop_events_in_window': float(window['normal_stop_events']),
            'anomaly_density': float(anomaly_density),
            'tgid_resolution_fallback': 1.0 if window['tid_fallback_used'] else 0.0,
            'tgid_resolution_fallback_count': float(self.tgid_resolution_fallback_count),
        }

        stage1_score = self.context_pipeline.compute_stage1_score(raw_features)
        band = self.context_pipeline.assign_band(stage1_score)

        profile_summary = self.context_pipeline.profile_summary_snapshot(scope_id, executable_key)

        excluded = not self.scope_baseline_mature
        exclusion_reason = 'scope_baseline_not_mature' if excluded else 'none'

        case_id = self.context_pipeline.make_case_id([
            scope_id,
            executable_key,
            process_id,
            trigger_tid,
            window['open_ts_ns'],
            window['anomaly_events'],
        ])

        candidate = {
            'case_id': case_id,
            'experiment': {
                'scope_mode': 'container' if self.scope_mode == defs.SCOPE_MODE_CONTAINER else 'host',
                'context_enabled': self.context_enabled,
                'scope_baseline_mature': self.scope_baseline_mature,
            },
            'window': {
                'open_reason': 'first_anomaly_event',
                'open_ts_ns': int(window['open_ts_ns']),
                'last_signal_ts_ns': int(window['last_anomaly_ts_ns']),
                'close_ts_ns': int(close_ts_ns),
                'close_reason': close_reason,
                'duration_ms': float(round(duration_ms, 3)),
            },
            'process': {
                'pid': int(pid),
                'tid': int(tid),
                'ppid': int(ppid),
                'tgid': int(pid),
                'trigger_tid': int(trigger_tid),
                'last_trigger_tid': int(last_trigger_tid),
                'exe': str(exe),
                'executable_key': int(executable_key),
            },
            'scope_profile': {
                'scope_id': int(scope_id),
                'profile_key': int(profile_key),
                'profile_status': int(profile_status),
                'profile_exists_at_open': bool(window['profile_exists_at_open']),
                'profile_seen_before': bool(window['profile_seen_before']),
                'profile_is_normal_at_open': bool(window['profile_is_normal_at_open']),
                'profile_is_normal_at_close': self._is_normal_profile_status(profile_status),
                'train_count': int(train_count),
                'last_mod_count': int(last_mod_count),
                'profile_count': int(profile_count),
                'profile_anomaly_count': int(profile_anomaly_count),
                'sequences': int(sequences),
                'normal_time_ns': int(normal_time_ns),
            },
            'raw_stage1_features': raw_features,
            'profile_window_summary': profile_summary,
            'routing': {
                'excluded_from_primary': excluded,
                'exclusion_reason': exclusion_reason,
                'band': band,
                'thresholds': {
                    'T_candidate': self.stage1_t_candidate,
                    'T_high': self.stage1_t_high,
                    'C_downgrade': self.stage2_c_downgrade,
                },
                'routing_normality_source': 'profile_is_normal_at_open',
            },
            'decision': {
                'stage1_score': stage1_score,
                'adjudicator_called': False,
                'adjudicator_result': 'skipped',
                'adjudicator_confidence': 0.0,
                'reason_code': 'none',
                'downgrade_applied': False,
                'final_binary_decision': 'not_detected',
            },
            'latency': {
                'window_close_to_stage1_ms': float(round((time.time_ns() - close_ts_ns) / 1e6, 3)),
                'adjudicator_ms': 0.0,
                'total_finalize_ms': 0.0,
            },
        }

        candidate = self.context_pipeline.finalize_decision(candidate)
        self.context_pipeline.update_profile_summary(
            scope_id,
            executable_key,
            stage1_score,
            anomaly_density,
        )
        candidate['latency']['total_finalize_ms'] = float(round((time.time_ns() - t0_ns) / 1e6, 3))
        self.context_pipeline.write_case(candidate)

        logger.audit(
            f"Case {candidate['case_id']} finalized: pid={pid} tid={tid} trigger_tid={trigger_tid} "
            f"scope={scope_id} profile={profile_key} score={stage1_score:.3f} band={band} "
            f"decision={candidate['decision']['final_binary_decision']} "
            f"fallback_tgid={window['tid_fallback_used']} close={close_reason}"
        )

    def change_setting(self, setting: EBPH_SETTINGS, value: int) -> int:
        """
        Change a @setting in the BPF program to @value if it is an integer >= 0.
        """
        if value < 0:
            logger.error(
                f'Value for {setting.name} must be a positive integer.'
            )
            return -1

        rc = Lib.set_setting(setting, value)
        err = os.strerror(ct.get_errno())

        if rc < 0:
            logger.error(f'Failed to set {setting.name} to {value}: {err}')
        if rc == 1:
            logger.info(f'{setting.name} is already set to {value}.')
        if rc == 0:
            logger.info(f'{setting.name} set to {value}.')
        return rc

    def get_setting(self, setting: EBPH_SETTINGS) -> Optional[int]:
        """
        Get @setting from the BPF program.
        """
        try:
            return self.bpf['_ebph_settings'][ct.c_uint64(setting)].value
        except (KeyError, IndexError):
            logger.error(f'Failed to get {setting.name}: Key does not exist')
        return None

    def start_monitoring(self, silent=False) -> int:
        """
        Start monitoring the system. (Equivalent to setting MONITORING to 1).
        """
        if self.get_setting(EBPH_SETTINGS.MONITORING) and not silent:
            logger.info('System is already being monitored.')
            return 1
        rc = Lib.set_setting(EBPH_SETTINGS.MONITORING, True)
        err = os.strerror(ct.get_errno())
        if rc < 0 and not silent:
            logger.error(f'Failed to start monitoring: {err}')
        if rc == 0 and not silent:
            logger.info('Started monitoring the system.')
        return rc

    def stop_monitoring(self, silent=False) -> int:
        """
        Stop monitoring the system. (Equivalent to setting MONITORING to 0).
        """
        if not self.get_setting(EBPH_SETTINGS.MONITORING) and not silent:
            logger.info('System is not being monitored.')
            return 1
        rc = Lib.set_setting(EBPH_SETTINGS.MONITORING, False)
        err = os.strerror(ct.get_errno())
        if rc < 0 and not silent:
            logger.error(f'Failed to stop monitoring: {err}')
        if rc == 0 and not silent:
            logger.info('Stopped monitoring the system.')
        return rc

    def save_profiles(self) -> Tuple[int, int]:
        """
        Save all profiles.
        """
        saved = 0
        error = 0

        logger.info('Saving profiles...')

        for k in self.bpf['profiles'].keys():
            key = k.value
            exe = self.profile_key_to_exe[key]
            scope_id = self.get_profile_scope_id(key)
            fname = f'{scope_id}_{key}' if self.scope_mode == defs.SCOPE_MODE_CONTAINER else f'{key}'
            try:
                profile = EBPHProfileStruct.from_bpf(
                    self.bpf,
                    exe.encode('ascii'),
                    key,
                    scope_id=scope_id,
                    executable_key=self.get_profile_executable_key(key),
                )
                with open(os.path.join(defs.EBPH_DATA_DIR, fname), 'wb') as f:
                    f.write(profile)
                logger.debug(f'Successfully saved profile {fname} ({exe}).')
            except Exception as e:
                logger.error(
                    f'Unable to save profile {fname} ({exe}).', exc_info=e
                )
                error += 1
            saved += 1
        logger.info(f'Saved {saved} profiles successfully!')
        return saved, error

    def load_profiles(self) -> Tuple[int, int]:
        """
        Load all profiles.
        """
        loaded = 0
        error = 0

        logger.info('Loading profiles...')
        # If we are monitoring, stop
        monitoring = self.get_setting(EBPH_SETTINGS.MONITORING)

        if monitoring:
            self.stop_monitoring()

        for fname in os.listdir(defs.EBPH_DATA_DIR):
            try:
                profile = EBPHProfileStruct()
                with open(os.path.join(defs.EBPH_DATA_DIR, fname), 'rb') as f:
                    f.readinto(profile)
                # Wrong version
                if profile.magic != calculate_profile_magic():
                    logger.debug(f'Wrong magic number for profile {fname}, skipping.')
                    continue
                profile.load_into_bpf(self.bpf)
                self.profile_key_to_exe[profile.profile_key] = profile.exe.decode('ascii')
                exe = self.profile_key_to_exe[profile.profile_key]
                logger.debug(f'Successfully loaded profile {fname} ({exe}).')
            except Exception as e:
                logger.error(f'Unable to load profile {fname}.', exc_info=e)
                error += 1
            loaded += 1

        # If we were monitoring, resume
        if monitoring:
            self.start_monitoring()
        logger.info(f'Loaded {loaded} profiles successfully!')
        return loaded, error

    def get_full_profile(self, key: int) -> EBPHProfileStruct:
        """
        Get a profile indexed by @key from the BPF program, INCLUDING its
        flags and return it as an EBPHProfileStruct.
        """
        exe = self.profile_key_to_exe[key]
        return EBPHProfileStruct.from_bpf(self.bpf, exe.encode('ascii'), key)

    def get_profile(self, key: int) -> ct.Structure:
        """
        Get just the profile struct indexed by @key from the BPF program.
        """
        return self.bpf['profiles'][ct.c_uint64(key)]

    def get_process(self, pid: int) -> ct.Structure:
        """
        Get a task_state indexed by @pid from the BPF program.
        """
        return self.bpf['task_states'][ct.c_uint32(pid)]

    def get_profile_scope_id(self, key: int) -> int:
        try:
            return self.bpf['profile_scope_ids'][ct.c_uint64(key)].value
        except Exception:
            return 0

    def get_profile_executable_key(self, key: int) -> int:
        try:
            return self.bpf['profile_executable_keys'][ct.c_uint64(key)].value
        except Exception:
            return key

    def normalize_profile(self, profile_key: int):
        """
        Normalize the profile indexed by @profile_key.
        """
        try:
            rc = Lib.normalize_profile(profile_key)
        except Exception as e:
            logger.error(f'Unable to normalize profile.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to normalize profile: {os.strerror(ct.get_errno())}')
        return rc

    def normalize_process(self, pid: int):
        """
        Normalize the process indexed by @pid.
        """
        try:
            rc = Lib.normalize_process(pid)
        except Exception as e:
            logger.error(f'Unable to normalize process {pid}.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to normalize process {pid}: {os.strerror(ct.get_errno())}')
        return rc

    def sensitize_profile(self, profile_key: int):
        """
        Sensitize the profile indexed by @profile_key.
        """
        try:
            rc = Lib.sensitize_profile(profile_key)
        except Exception as e:
            logger.error(f'Unable to sensitize profile.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to sensitize profile: {os.strerror(ct.get_errno())}')
            return rc
        exe = self.profile_key_to_exe[profile_key]
        logger.info(f'Sensitized profile {exe}. Training data reset.')
        return rc

    def sensitize_process(self, pid: int):
        """
        Sensitize the process indexed by @pid.
        """
        try:
            rc = Lib.sensitize_process(pid)
        except Exception as e:
            logger.error(f'Unable to sensitize process {pid}.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to sensitize process {pid}: {os.strerror(ct.get_errno())}')
            return rc
        try:
            process = self.get_process(pid)
            exe = self.profile_key_to_exe[process.profile_key]
        except (KeyError, IndexError):
            exe = '[unknown]'
        logger.info(f'Sensitized PID {pid} ({exe}). Training data reset.')
        return rc

    def tolerize_profile(self, profile_key: int):
        """
        Tolerize the profile indexed by @profile_key.
        """
        try:
            rc = Lib.tolerize_profile(profile_key)
        except Exception as e:
            logger.error(f'Unable to tolerize profile.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to tolerize profile: {os.strerror(ct.get_errno())}')
            return rc
        exe = self.profile_key_to_exe[profile_key]
        logger.info(f'Tolerized profile {exe}. Stopped normal monitoring.')
        return rc

    def tolerize_process(self, pid: int):
        """
        Tolerize the process indexed by @pid.
        """
        try:
            rc = Lib.tolerize_process(pid)
        except Exception as e:
            logger.error(f'Unable to tolerize process {pid}.', exc_info=e)
            return -1
        if rc < 0:
            logger.error(f'Unable to tolerize process {pid}: {os.strerror(ct.get_errno())}')
            return rc
        try:
            process = self.get_process(pid)
            exe = self.profile_key_to_exe[process.profile_key]
        except (KeyError, IndexError):
            exe = '[unknown]'
        logger.info(f'Tolerized PID {pid} ({exe}). Stopped normal monitoring.')
        return rc

    def _register_ring_buffers(self) -> None:
        logger.info('Registering ring buffers...')

        @ringbuf_callback(self.bpf, 'new_profile_events')
        def new_profile_events(ctx, event, size):
            """
            new_profile_events.

            Callback for new profile creation.
            Logs creation and caches key -> pathname mapping
            for later use.
            """
            pathname = event.pathname.decode('utf-8')
            try:
                pass
            except Exception:
                pass
            self.profile_key_to_exe[event.profile_key] = pathname

            if self.debug:
                logger.info(
                    f'Created new profile for {pathname} ({event.profile_key}, scope={event.scope_id}).'
                )
            else:
                logger.info(f'Created new profile for {pathname} (scope={event.scope_id}).')

        @ringbuf_callback(self.bpf, 'anomaly_events')
        def anomaly_events(ctx, event, size):
            """
            anomaly_events.

            Log anomalies.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            number = event.syscall
            name = EBPH_LSM.get_name(number)
            misses = event.misses
            pid = event.pid
            count = event.task_count

            window = self._get_or_open_window(event)
            window['last_anomaly_ts_ns'] = time.time_ns()
            window['last_trigger_tid'] = int(event.pid)
            window['trigger_tids'].add(int(event.pid))
            window['anomaly_events'] += 1
            window['anomaly_miss_sum'] += int(misses)
            window['anomaly_miss_max'] = max(window['anomaly_miss_max'], int(misses))
            window['distinct_lsm_anomalies'].add(int(number))
            window['task_count_last'] = int(count)

            logger.audit(
                f'Anomalous {name} ({misses} misses) '
                f'in PID {pid} ({exe}, scope={event.scope_id}) after {count} calls.'
            )

        @ringbuf_callback(self.bpf, 'new_sequence_events')
        def new_sequence_events(ctx, event, size):
            """
            new_sequence_events.

            Log new sequences.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            if not exe:
                exe = event.profile_key
            sequence = [
                EBPH_LSM.get_name(call)
                for call in event.sequence
                if call != defs.BPF_DEFINES['EBPH_EMPTY']
            ]
            sequence = reversed(sequence)
            pid = event.pid
            profile_count = event.profile_count
            task_count = event.task_count

            logger.debug(
                f'New sequence in PID {pid} ({exe}, scope={event.scope_id}), task count = {task_count}, profile count = {profile_count}.'
            )
            logger.sequence(f'PID {pid} ({exe}): ' + ', '.join(sequence))
            self._enrich_open_window(event.scope_id, event.profile_key, event.pid, 'new_sequence_events', 1)

        @ringbuf_callback(self.bpf, 'start_normal_events')
        def start_normal_events(ctx, event, size):
            """
            start_normal_events.

            Log when a profile starts normal monitoring.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            profile_count = event.profile_count
            sequences = event.sequences
            train_count = event.train_count
            last_mod_count = event.last_mod_count

            in_task = event.in_task
            task_count = event.task_count
            pid = event.pid

            if in_task:
                self._enrich_open_window(event.scope_id, event.profile_key, event.pid, 'normal_start_events', 1)
                logger.info(
                    f'PID {pid} ({exe}) now has {train_count} '
                    f'training calls and {last_mod_count} since last '
                    f'change ({profile_count} total).'
                )
                logger.info(
                    f'Starting normal monitoring in PID {pid} ({exe}) '
                    f'after {task_count} calls ({sequences} sequences).'
                )
            else:
                logger.info(
                    f'{exe} now has {train_count} '
                    f'training calls and {last_mod_count} since last '
                    f'change ({profile_count} total).'
                )
                logger.info(
                    f'Starting normal monitoring for {exe} '
                    f'with {sequences} sequences.'
                )

        @ringbuf_callback(self.bpf, 'stop_normal_events')
        def stop_normal_events(ctx, event, size):
            """
            stop_normal_events.

            Log when a profile stops normal monitoring.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            anomalies = event.anomalies
            anomaly_limit = event.anomaly_limit

            in_task = event.in_task
            task_count = event.task_count
            pid = event.pid

            if in_task:
                self._enrich_open_window(event.scope_id, event.profile_key, event.pid, 'normal_stop_events', 1)
                logger.info(
                    f'Stopped normal monitoring in PID {pid} ({exe}) '
                    f'after {task_count} calls and {anomalies} anomalies '
                    f'(limit {anomaly_limit}).'
                )
            else:
                logger.info(
                    f'Stopped normal monitoring for {exe} '
                    f'with {anomalies} anomalies (limit {anomaly_limit}).'
                )

        @ringbuf_callback(self.bpf, 'tolerize_limit_events', ratelimit_per_sec=10)
        def tolerize_limit_events(ctx, event, size):
            """
            tolerize_limit_events.

            Callback for when a process exceeds its tolerize limit.
            """
            profile_key = event.profile_key
            pid = event.pid
            lfc = event.lfc
            exe = self.profile_key_to_exe[profile_key]
            self._enrich_open_window(event.scope_id, event.profile_key, event.pid, 'tolerize_limit_hits', 1)

            logger.info(f'Tolerize limit exceeded for PID {pid} ({exe}, scope={event.scope_id}), LFC is {lfc}. Training data reset.')

    def _generate_syscall_defines(self, flags: List[str]) -> None:
        from bcc.syscall import syscalls

        for num, name in syscalls.items():
            name = name.decode('utf-8').upper()
            self.syscall_number_to_name[num] = name
            definition = f'-DEBPH_SYS_{name}={num}'
            flags.append(definition)

    def _calculate_boot_epoch(self):
        boot_time = time.monotonic() * int(1e9)
        boot_epoch = time.time() * int(1e9) - boot_time
        return int(boot_epoch)

    def _bootstrap_processes(self):
        should_bootstrap = (
            self.bootstrap_mode == 'always' or
            (
                self.bootstrap_mode == 'auto' and
                self.scope_mode == defs.SCOPE_MODE_HOST
            )
        )

        if not should_bootstrap:
            logger.info(f'Skipping userspace bootstrap (bootstrap_mode={self.bootstrap_mode}, scope_mode={self.scope_mode}).')
            return

        for profile_key, scope_id, executable_key, exe, pid, tid in running_processes(self.scope_mode):
            logger.debug(f'Found process {pid},{tid} running {exe} ({profile_key}, scope={scope_id})')
            Lib.bootstrap_process(profile_key, scope_id, executable_key, tid, pid, exe.encode('ascii'))
            self.bpf.ring_buffer_consume()

    def _sync_container_scope_ids(self) -> None:
        if self.scope_mode != defs.SCOPE_MODE_CONTAINER:
            return

        try:
            scope_map = self.bpf['container_scope_ids']
            scope_map.clear()
            one = ct.c_ubyte(1)
            for scope_id in list_container_scope_ids():
                scope_map[ct.c_uint64(scope_id)] = one
        except Exception as e:
            logger.debug('Unable to sync container scope IDs', exc_info=e)

    def _set_cflags(self) -> None:
        logger.info('Setting cflags...')

        self.cflags.append(f'-I{defs.BPF_DIR}')
        self.cflags.append(f'-DEBPH_SCOPE_MODE={self.scope_mode}')
        for k, v in defs.BPF_DEFINES.items():
            self.cflags.append(f'-D{k}={v}')

        if self.debug:
            self.cflags.append('-DEBPH_DEBUG')

        for flag in self.cflags:
            logger.debug(f'Using {flag}...')

        self.cflags.append(
            f'-DEBPH_BOOT_EPOCH=((u64){self._calculate_boot_epoch()})'
        )
        self._generate_syscall_defines(self.cflags)

    def _load_bpf(self) -> None:
        assert self.bpf is None
        logger.info('Loading BPF program...')

        with open(defs.BPF_PROGRAM_C, 'r') as f:
            bpf_text = f.read()

        self.bpf = BPF(
            text=bpf_text, usdt_contexts=[Lib.usdt_context], cflags=self.cflags
        )
        # FIXME: BPF cleanup function is segfaulting, so unregister it for now.
        # It actually doesn't really do anything particularly useful.
        atexit.unregister(self.bpf.cleanup)

    def _cleanup(self) -> None:
        if self.auto_save:
            self.save_profiles()
        del self.bpf
        self.bpf = None
