"""Unit tests for chef_detection.test_data_generator."""

from __future__ import annotations

import json

from chef_detection.test_data_generator import (
    SyntheticDataSet,
    SyntheticEvent,
    generate_test_data_deterministic,
    to_jsonl,
)

# ---------------------------------------------------------------------------
# Deterministic generation - known technique
# ---------------------------------------------------------------------------

_LSASS_RULE = {
    "title": "LSASS Memory Access - Credential Dumping",
    "logsource": {"category": "process_access", "product": "windows"},
    "detection": {
        "selection": {"TargetImage|endswith": "\\lsass.exe"},
        "condition": "selection",
    },
    "level": "high",
}


def test_generate_deterministic_t1003_001_has_positive_events() -> None:
    ds = generate_test_data_deterministic("T1003.001", _LSASS_RULE)
    assert len(ds.positive_events) > 0


def test_generate_deterministic_t1003_001_has_negative_events() -> None:
    ds = generate_test_data_deterministic("T1003.001", _LSASS_RULE)
    assert len(ds.negative_events) > 0


def test_generate_deterministic_t1003_001_technique_id() -> None:
    ds = generate_test_data_deterministic("T1003.001", _LSASS_RULE)
    assert ds.technique_id == "T1003.001"


# ---------------------------------------------------------------------------
# Deterministic generation - unknown technique
# ---------------------------------------------------------------------------


def test_generate_deterministic_unknown_returns_empty() -> None:
    ds = generate_test_data_deterministic("T9999.999", {"title": "Unknown"})
    assert ds.technique_id == "T9999.999"
    assert ds.positive_events == []
    assert ds.negative_events == []


# ---------------------------------------------------------------------------
# to_jsonl
# ---------------------------------------------------------------------------


def test_to_jsonl_produces_valid_jsonl() -> None:
    ds = generate_test_data_deterministic("T1003.001", _LSASS_RULE)
    jsonl = to_jsonl(ds)
    lines = jsonl.strip().split("\n")
    assert len(lines) == len(ds.positive_events) + len(ds.negative_events)
    for line in lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
        assert "_meta" in parsed
        assert "technique_id" in parsed["_meta"]


def test_to_jsonl_empty_dataset_produces_no_output() -> None:
    ds = generate_test_data_deterministic("T9999.999", {"title": "Unknown"})
    jsonl = to_jsonl(ds)
    assert jsonl == ""


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


def test_test_event_model_validates() -> None:
    event = SyntheticEvent(
        event_type="process_creation",
        fields={"Image": "C:\\Windows\\cmd.exe", "CommandLine": "whoami"},
        is_positive=True,
        description="Test event",
    )
    assert event.event_type == "process_creation"
    assert event.is_positive is True


def test_test_data_set_model_validates() -> None:
    ds = SyntheticDataSet(
        technique_id="T1003.001",
        rule_title="Test Rule",
        positive_events=[
            SyntheticEvent(
                event_type="process_access",
                fields={"TargetImage": "lsass.exe"},
                is_positive=True,
                description="Positive test",
            ),
        ],
        negative_events=[],
    )
    assert ds.technique_id == "T1003.001"
    assert len(ds.positive_events) == 1
    assert len(ds.negative_events) == 0
