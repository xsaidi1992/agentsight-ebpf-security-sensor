from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider la persistance JSONL, l’Unicode, les métadonnées et les erreurs de corruption.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from pathlib import Path

import pytest

from src.storage import JsonlEventStore


# [TESTS / BESOIN A/F/P/T] Fonction `test_empty_batch_does_not_create_a_jsonl_file` : prouve
# automatiquement le scénario `test_empty_batch_does_not_create_a_jsonl_file`
# et protège le comportement contre les régressions.
def test_empty_batch_does_not_create_a_jsonl_file(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)

    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert store.append_many([]) == 0
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert path.exists() is False
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert store.read_all() == []


# [TESTS / BESOIN A/F/P/T] Fonction `test_jsonl_store_round_trips_unicode_and_batch_metadata` : prouve
# automatiquement le scénario
# `test_jsonl_store_round_trips_unicode_and_batch_metadata` et protège le
# comportement contre les régressions.
def test_jsonl_store_round_trips_unicode_and_batch_metadata(tmp_path: Path) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl", durable=True)

    written = store.append_many(
        [
            ("llm_interaction", "session-1", {"prompt": "Télécharger le rapport"}),
            ("os_event", "session-1", {"pid": 42}),
        ]
    )
    records = store.read_all()

    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert written == 2
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert [item["record_type"] for item in records] == ["llm_interaction", "os_event"]
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert records[0]["payload"]["prompt"] == "Télécharger le rapport"
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert records[0]["persisted_at"] == records[1]["persisted_at"]
    # [TESTS / BESOIN A/F/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert all(item["schema_version"] == 1 for item in records)


# [TESTS / BESOIN A/F/P/T] Fonction `test_jsonl_store_rejects_empty_labels_and_reports_corrupt_line` :
# prouve automatiquement le scénario
# `test_jsonl_store_rejects_empty_labels_and_reports_corrupt_line` et protège
# le comportement contre les régressions.
def test_jsonl_store_rejects_empty_labels_and_reports_corrupt_line(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEventStore(path)

    # [TESTS / BESOIN A/F/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="record_type"):
        store.append(" ", "s1", {"pid": 1})
    # [TESTS / BESOIN A/F/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="session_id"):
        store.append("os_event", " ", {"pid": 1})

    path.write_text('{"ok":true}\nnot-json\n', encoding="utf-8")
    # [TESTS / BESOIN A/F/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match=r"events\.jsonl:2"):
        store.read_all()
