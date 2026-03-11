from app.services.risk_engine import _simulation


def test_simulation_is_safe_read_only():
    sim = _simulation('ESC1-like', ['a'], 'impact', ['missing'], 'high')
    assert sim['safe_mode'] is True
    assert 'No exploitation' in sim['actions_performed']
