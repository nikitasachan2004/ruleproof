"""Unit tests for Sigma rule parsing and ATT&CK tag extraction."""

from pathlib import Path

from ruleproof.rules import load_rules, parse_sigma_file


def test_parse_sigma_file() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "rules"
    mimikatz_rule = fixtures_dir / "proc_creation_win_mimikatz.yml"

    rule = parse_sigma_file(mimikatz_rule)
    assert rule is not None
    assert rule.rule_id == "5b018596-f947-4972-87ad-d54d241773d4"
    assert rule.status == "stable"
    assert "T1003.001" in rule.techniques
    assert "T1003" in rule.techniques
    # Tactics like attack.credential_access should not be parsed as technique IDs
    assert "CREDENTIAL_ACCESS" not in rule.techniques


def test_load_rules_filtering() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "rules"

    # Default filter: stable and test only
    rules_default = load_rules(fixtures_dir, target_statuses={"stable", "test"})
    statuses = {r.status for r in rules_default}
    assert "stable" in statuses
    assert "test" in statuses
    assert "experimental" not in statuses

    # All statuses: includes experimental
    rules_all = load_rules(fixtures_dir, target_statuses=None)
    statuses_all = {r.status for r in rules_all}
    assert "experimental" in statuses_all


def test_parse_invalid_yaml(tmp_path: Path) -> None:
    bad_file = tmp_path / "corrupt.yml"
    bad_file.write_text("::: not valid yaml :::")
    assert parse_sigma_file(bad_file) is None
