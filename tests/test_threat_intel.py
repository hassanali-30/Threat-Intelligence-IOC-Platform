from threat_intel import parse_stix


def test_stix_file_hash_is_normalized_as_hash():
    indicators = parse_stix({
        "objects": [{
            "type": "indicator",
            "pattern": "[file:hashes.SHA-256 = 'ABCDEF0123456789']",
            "confidence": 90,
        }]
    })
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "hash"
    assert indicators[0].value == "abcdef0123456789"
