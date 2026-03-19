from ebph.context_pipeline import ContextPipeline


def test_stage1_band_assignment(tmp_path):
    cp = ContextPipeline(
        replay_root=str(tmp_path),
        scope_mode=0,
        context_enabled=True,
        scope_baseline_mature=True,
        t_candidate=2.0,
        t_high=8.0,
        c_downgrade=0.8,
        profile_summary_window=10,
    )

    low_score = cp.compute_stage1_score({'anomaly_events': 1, 'anomaly_density': 0.01})
    assert cp.assign_band(low_score) == 'low'

    cand_score = cp.compute_stage1_score({'anomaly_events': 5, 'anomaly_miss_sum': 4, 'anomaly_density': 0.2})
    assert cp.assign_band(cand_score) in {'candidate', 'high'}


def test_stub_deterministic_decision(tmp_path):
    cp = ContextPipeline(
        replay_root=str(tmp_path),
        scope_mode=0,
        context_enabled=True,
        scope_baseline_mature=True,
        t_candidate=2.0,
        t_high=8.0,
        c_downgrade=0.8,
        profile_summary_window=10,
    )

    candidate = {
        'routing': {'band': 'high'},
        'raw_stage1_features': {
            'anomaly_density': 0.05,
            'anomaly_miss_max': 1,
        },
        'decision': {},
        'latency': {},
    }

    out = cp.finalize_decision(candidate)
    assert out['decision']['final_binary_decision'] == 'not_detected'
    assert out['decision']['downgrade_applied'] is True


def test_profile_summary_key_scope_executable(tmp_path):
    cp = ContextPipeline(
        replay_root=str(tmp_path),
        scope_mode=1,
        context_enabled=True,
        scope_baseline_mature=True,
        t_candidate=2.0,
        t_high=8.0,
        c_downgrade=0.8,
        profile_summary_window=10,
    )

    cp.update_profile_summary(11, 22, stage1_score=3.0, anomaly_density=0.4)
    cp.update_profile_summary(11, 22, stage1_score=5.0, anomaly_density=0.2)
    snap = cp.profile_summary_snapshot(11, 22)
    assert snap['recent_case_count'] == 2
    assert snap['recent_avg_stage1_score'] == 4.0
