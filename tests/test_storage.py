from __future__ import annotations

from pathlib import Path

import pytest

from src.storage import JsonlEventStore


def test_empty_batch_does_not_create_a_jsonl_file(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)

    assert store.append_many([]) == 0
    assert path.exists() is False
    assert store.read_all() == []


def test_jsonl_store_round_trips_unicode_and_batch_metadata(tmp_path: Path) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl", durable=True)

    written = store.append_many(
        [
            ("llm_interaction", "session-1", {"prompt": "Télécharger le rapport"}),
            ("os_event", "session-1", {"pid": 42}),
        ]
    )
    records = store.read_all()

    assert written == 2
    assert [item["record_type"] for item in records] == ["llm_interaction", "os_event"]
    assert records[0]["payload"]["prompt"] == "Télécharger le rapport"
    assert records[0]["persisted_at"] == records[1]["persisted_at"]
    assert all(item["schema_version"] == 1 for item in records)


def test_jsonl_store_rejects_empty_labels_and_reports_corrupt_line(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)

    with pytest.raises(ValueError, match="record_type"):
        store.append(" ", "s1", {"pid": 1})
    with pytest.raises(ValueError, match="session_id"):
        store.append("os_event", " ", {"pid": 1})

    path.write_text('{"ok":true}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"events\.jsonl:2"):
        store.read_all()
