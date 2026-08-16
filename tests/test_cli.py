from envsafe.cli import redact, scan


def test_scan_flags_duplicate_and_sensitive_without_values():
    result = scan("# comment\nAPI_TOKEN=abc123\nAPI_TOKEN=second\nEMPTY=\n")
    kinds = {item["kind"] for item in result["findings"]}
    assert {"sensitive", "duplicate", "empty"} <= kinds
    assert "abc123" not in str(result)


def test_redact_preserves_comments_and_keys():
    output = redact("# keep\nexport API_KEY=secret # note\nNAME=demo\n")
    assert output == "# keep\nexport API_KEY=\nNAME=\n"
