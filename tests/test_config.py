from vea_challenger.config import Settings


def test_loop_settings_defaults():
    s = Settings()
    assert s.min_challenge_agreement == 2
    assert s.liveness_epochs == 12
    assert s.genesis_lookback_blocks is None


def test_challenge_on_ambiguity_is_off_by_default():
    """[O3]: the deadline override is opt-in."""
    assert Settings().challenge_on_ambiguity is False
