from threat_intel import (
    IOC,
    IOCStore,
    freshness_factor,
    is_expired,
    normalize_value,
    score_ioc,
)


def test_normalization():
    assert normalize_value("domain", "Example.COM.") == "example.com"
    assert normalize_value("hash", "ABCDEF") == "abcdef"


def test_score_is_bounded_and_freshness_decays():
    ioc = IOC("ip", "203.0.113.10", "trusted", 1.0, "high", last_seen=1000)
    assert 0 < score_ioc(ioc, current=1000) <= 100
    assert freshness_factor(1000, current=1000 + 90 * 86400) < freshness_factor(1000, current=1000)


def test_expiration():
    ioc = IOC("domain", "expired.example", expires_at=10)
    assert is_expired(ioc, current=11)
    assert not is_expired(ioc, current=9)


def test_correlation_uses_type_specific_normalization(tmp_path):
    store = IOCStore(str(tmp_path / "intel.db"))
    try:
        store.upsert(IOC("domain", "example.com", "trusted", 1.0, "high"))
        store.upsert(IOC("url", "https://example.test/path", "trusted", 1.0, "high"))
        matches = store.correlate([
            "EXAMPLE.COM.",
            "https://EXAMPLE.test/path#section",
        ])
        assert {(item["indicator_type"], item["value"]) for item in matches} == {
            ("domain", "example.com"),
            ("url", "https://example.test/path"),
        }
    finally:
        store.close()
