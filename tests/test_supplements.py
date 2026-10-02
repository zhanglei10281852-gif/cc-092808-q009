from __future__ import annotations

import pytest

from app.core.errors import ConflictError, ValidationError
from app.database import get_connection, transaction
from app.forensics.service import ForensicService


def make_agency(service: ForensicService, suffix: str) -> dict:
    return service.forensic_cases.create_agency({
        "agency_code": f"ORG-{suffix}", "agency_name": "市公安局物证中心", "jurisdiction_code": "CN",
        "contact_address": "政务区司法路 8 号", "licensed_on": "2025-10-02", "accreditation_no": None,
        "restrictions": {},
    })


def make_case(service: ForensicService, suffix: str, agency_id: int, *, passport: dict | None = None) -> dict:
    forensic_case = service.forensic_cases.create_forensic_case({
        "case_no": f"CASE-{suffix}", "case_name": "身份关系鉴定", "discipline": "法医物证",
        "entrusted_matter": "亲缘关系鉴定", "agency_id": agency_id, "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": passport if passport is not None else {"commission_document": f"DOC-{suffix}"},
        "created_by": "登记员",
    })
    return service.forensic_cases.transition(forensic_case["id"], {
        "target_status": "accepted", "reason": "资料齐全", "expected_version": 1, "actor": "审核员",
    })


def register_package(service: ForensicService, suffix: str, agency_id: int, **overrides) -> dict:
    payload = {
        "package_no": f"PKG-{suffix}", "idempotency_key": f"pkg-key-{suffix}", "agency_id": agency_id,
        "document_no": f"DOC-{suffix}", "case_no_alias": "", "seal_nos": [], "notes": "", "created_by": "登记员",
    }
    payload.update(overrides)
    return service.supplements.register_package(payload)


def test_candidates_carry_evidence_and_confirm_receives_items(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "C1")
        forensic_case = make_case(service, "C1", agency["id"])
        result = register_package(
            service, "C1", agency["id"],
            document_no="doc-c1 ", case_no_alias="CASE-C1", seal_nos=["SEAL-C1"],
        )
        package = result["package"]
        assert result["replayed"] is False
        assert package["status"] == "pending"
        assert len(package["candidates"]) == 1
        candidate = package["candidates"][0]
        assert candidate["case"]["id"] == forensic_case["id"]
        evidence_types = {item["type"] for item in candidate["evidence"]}
        assert {"document_no", "case_no_alias", "agency"} <= evidence_types
        confirmed = service.supplements.confirm(package["id"], {
            "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "confirmed"
        assert confirmed["matched_case"]["id"] == forensic_case["id"]
        item = service.supplements.add_item(package["id"], {
            "specimen_no": "SP-C1-NEW", "received_year": 2026, "initial_quantity": 3,
            "packaging": "防拆封袋", "created_by": "登记员",
        })
        assert item["replayed"] is False
        assert item["specimen"]["case_id"] == forensic_case["id"]
        replay = service.supplements.add_item(package["id"], {
            "specimen_no": "SP-C1-NEW", "received_year": 2026, "initial_quantity": 3,
            "packaging": "防拆封袋", "created_by": "登记员",
        })
        assert replay["replayed"] is True
        detail = service.repository.forensic_case_detail(forensic_case["id"])
        assert any(event["event_type"] == "supplement_confirmed" for event in detail["events"])


def test_package_without_candidates_stays_quarantined(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "Q1")
        forensic_case = make_case(service, "Q1", agency["id"])
        result = register_package(service, "Q1-OTHER", agency["id"], document_no="UNRELATED-9")
        package = result["package"]
        assert package["status"] == "quarantined"
        assert package["candidates"] == []
        with pytest.raises(ValidationError):
            service.supplements.confirm(package["id"], {
                "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
            })
        confirmed = service.supplements.confirm(package["id"], {
            "case_id": forensic_case["id"], "reason": "侦查机关电话核实为同一鉴定事项",
            "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "confirmed"


def test_registration_is_idempotent_and_rejects_key_reuse(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "I1")
        make_case(service, "I1", agency["id"])
        first = register_package(service, "I1", agency["id"])
        second = register_package(service, "I1", agency["id"])
        assert second["replayed"] is True
        assert second["package"]["id"] == first["package"]["id"]
        count = connection.execute("SELECT COUNT(*) FROM supplement_packages").fetchone()[0]
        assert count == 1
        with pytest.raises(ConflictError):
            service.supplements.register_package({
                "package_no": "PKG-I1-DIFF", "idempotency_key": "pkg-key-I1", "agency_id": agency["id"],
                "document_no": "OTHER", "case_no_alias": "", "seal_nos": [], "notes": "", "created_by": "登记员",
            })


def test_item_intake_requires_confirmation(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "B1")
        make_case(service, "B1", agency["id"])
        package = register_package(service, "B1", agency["id"])["package"]
        with pytest.raises(ConflictError):
            service.supplements.add_item(package["id"], {
                "specimen_no": "SP-B1", "received_year": 2026, "initial_quantity": 1, "created_by": "登记员",
            })


def test_seal_conflict_enters_reasoned_resolution(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "S1")
        case_a = make_case(service, "S1A", agency["id"])
        case_b = make_case(service, "S1B", agency["id"])
        first = register_package(service, "S1A", agency["id"], seal_nos=["SEAL-9"])
        service.supplements.confirm(first["package"]["id"], {
            "case_id": case_a["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        second = register_package(service, "S1B", agency["id"], document_no="", case_no_alias="", seal_nos=["SEAL-9"])
        assert second["package"]["status"] == "pending"
        candidate_ids = [item["case"]["id"] for item in second["package"]["candidates"]]
        assert candidate_ids == [case_a["id"]]
        conflicted = service.supplements.confirm(second["package"]["id"], {
            "case_id": case_b["id"], "reason": "侦查机关坚持归入新案", "expected_version": 1, "actor": "登记员",
        })
        assert conflicted["status"] == "conflict"
        assert "seal_conflict" in conflicted["conflict"]["types"]
        assert conflicted["conflict"]["seal_conflict"][0]["case_no"] == case_a["case_no"]
        rejected = service.supplements.resolve_conflict(second["package"]["id"], {
            "action": "reject", "reason": "封识归属存疑，材料保持隔离",
            "expected_version": conflicted["version"], "actor": "案件审核员",
        })
        assert rejected["status"] == "quarantined"
        assert rejected["resolved_by"] == "案件审核员"
        third = register_package(service, "S1C", agency["id"], document_no="", case_no_alias="", seal_nos=["SEAL-9"])
        overridden = service.supplements.confirm(third["package"]["id"], {
            "case_id": case_b["id"], "reason": "坚持归入新案", "expected_version": 1, "actor": "登记员",
        })
        resolved = service.supplements.resolve_conflict(third["package"]["id"], {
            "action": "override_confirm", "reason": "核实为同批次不同检材，封识号重复登记",
            "expected_version": overridden["version"], "actor": "案件审核员",
        })
        assert resolved["status"] == "confirmed"
        assert resolved["matched_case"]["id"] == case_b["id"]
        owners = service.repository.seal_owners(["SEAL-9"])
        assert {row["case_id"] for row in owners} == {case_a["id"], case_b["id"]}


def test_closed_case_conflict_and_reopen_on_override(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "R1")
        signed_case = make_case(service, "R1A", agency["id"])
        service.forensic_cases.sign_report(signed_case["id"], {"expected_version": 2, "actor": "鉴定人"})
        package = register_package(service, "R1A", agency["id"])["package"]
        conflicted = service.supplements.confirm(package["id"], {
            "case_id": signed_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert conflicted["status"] == "conflict"
        assert "case_closed" in conflicted["conflict"]["types"]
        resolved = service.supplements.resolve_conflict(package["id"], {
            "action": "override_confirm", "reason": "补充对照样本，重新启动检验",
            "expected_version": conflicted["version"], "actor": "案件审核员",
        })
        assert resolved["status"] == "confirmed"
        retired_case = make_case(service, "R1B", agency["id"])
        service.forensic_cases.transition(retired_case["id"], {
            "target_status": "retired", "reason": "重复建档", "expected_version": 2, "actor": "审核员",
        })
        package_b = register_package(service, "R1B", agency["id"])["package"]
        conflicted_b = service.supplements.confirm(package_b["id"], {
            "case_id": retired_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert conflicted_b["status"] == "conflict"
        resolved_b = service.supplements.resolve_conflict(package_b["id"], {
            "action": "override_confirm", "reason": "补送材料到达，重启案件审查",
            "expected_version": conflicted_b["version"], "actor": "案件审核员",
        })
        assert resolved_b["status"] == "confirmed"
        reopened = service.repository.require_forensic_case(retired_case["id"])
        assert reopened["status"] == "quarantine"
        events = service.repository.forensic_case_detail(retired_case["id"])["events"]
        assert any(event["event_type"] == "reopened" for event in events)


def test_merge_execute_moves_references_and_keeps_history(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "M1")
        target = make_case(service, "M1A", agency["id"], passport={"commission_document": "DOC-M1A"})
        source = make_case(service, "M1B", agency["id"], passport={"commission_document": "DOC-M1B"})
        location = service.custody.create_location({
            "location_code": "VAULT-M1", "facility": "检材保管室", "room": "冷藏区", "rack": "R1", "shelf": "S1",
            "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
        })
        specimen = service.custody.create_specimen({
            "specimen_no": "SP-M1", "case_id": source["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 50, "integrity_percent": 100,
            "packaging": "防拆封袋", "sealed_on": "2026-09-02", "created_by": "登记员",
        })
        service.custody.place_specimen({
            "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 50,
            "container_code": "BOX-M1", "idempotency_key": "place-m1-0001", "actor": "保管员",
        })
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "reason": "同一鉴定事项误建两案", "actor": "系统管理员",
        })
        assert preview["status"] == "previewed"
        plan = preview["plan"]
        assert [item["specimen_no"] for item in plan["references"]["specimens"]] == ["SP-M1"]
        assert plan["followed_references"]["custody_events"] == 1
        assert plan["blocking_issues"] == []
        assert plan["field_options"]["entrusted_matter"]["differ"] is False
        with pytest.raises(ConflictError):
            service.merges.preview({
                "source_case_id": source["id"], "target_case_id": target["id"],
                "reason": "重复预演", "actor": "系统管理员",
            })
        executed = service.merges.execute(preview["id"], {
            "field_decisions": {"passport": "source", "case_name": "target"},
            "expected_version": 1, "actor": "系统管理员",
        })
        assert executed["status"] == "executed"
        result = executed["result"]
        assert result["moved_specimens"][0]["specimen_no"] == "SP-M1"
        assert result["fields_updated"]["passport"]["after"] == {"commission_document": "DOC-M1B"}
        moved_specimen = service.repository.require_specimen(specimen["id"])
        assert moved_specimen["case_id"] == target["id"]
        movements = service.repository.specimen_detail(specimen["id"])["movements"]
        assert [item["id"] for item in movements] == [1]
        assert movements[0]["movement_type"] == "入库"
        source_after = service.repository.require_forensic_case(source["id"])
        assert source_after["status"] == "retired"
        assert source_after["merged_into_case_id"] == target["id"]
        target_after = service.repository.forensic_case_detail(target["id"])
        assert target_after["passport"] == {"commission_document": "DOC-M1B"}
        assert target_after["merged_from"][0]["source_case_no"] == source["case_no"]
        resolved = service.repository.resolve_case_number(source["case_no"])
        assert resolved["resolution"] == "merged"
        assert resolved["merged_into"]["case_id"] == target["id"]
        audits = connection.execute(
            "SELECT action FROM audit_events WHERE resource_type='case_merge' ORDER BY id"
        ).fetchall()
        assert [row[0] for row in audits] == ["case_merge.previewed", "case_merge.executed"]
        with pytest.raises(ConflictError):
            service.merges.execute(preview["id"], {
                "field_decisions": {}, "expected_version": 2, "actor": "系统管理员",
            })


def test_merge_blocks_release_item_collision(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "L1")
        target = make_case(service, "L1A", agency["id"])
        source = make_case(service, "L1B", agency["id"])
        service.release.create_request({
            "request_no": "REL-L1", "requester": "法医物证实验室", "purpose": "补充检验取样",
            "items": [
                {"case_id": target["id"], "quantity": 5},
                {"case_id": source["id"], "quantity": 5},
            ],
        })
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "reason": "误建案件归并", "actor": "系统管理员",
        })
        assert preview["plan"]["blocking_issues"][0]["type"] == "release_item_collision"
        with pytest.raises(ConflictError) as excinfo:
            service.merges.execute(preview["id"], {
                "field_decisions": {}, "expected_version": 1, "actor": "系统管理员",
            })
        assert excinfo.value.context["blocking_issues"]


def test_merge_cancel_frees_source_and_version_is_checked(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "V1")
        target = make_case(service, "V1A", agency["id"])
        source = make_case(service, "V1B", agency["id"])
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "reason": "误建案件归并", "actor": "系统管理员",
        })
        with pytest.raises(ConflictError):
            service.merges.execute(preview["id"], {
                "field_decisions": {}, "expected_version": 99, "actor": "系统管理员",
            })
        cancelled = service.merges.cancel(preview["id"], {
            "reason": "核实后并非同一鉴定事项", "expected_version": 1, "actor": "系统管理员",
        })
        assert cancelled["status"] == "cancelled"
        again = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "reason": "重新确认后再次归并", "actor": "系统管理员",
        })
        assert again["status"] == "previewed"


def test_alias_resolution_and_audit_trail(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = make_agency(service, "A1")
        forensic_case = make_case(service, "A1", agency["id"])
        package = register_package(service, "A1", agency["id"], case_no_alias="2026-鉴-001")["package"]
        service.supplements.confirm(package["id"], {
            "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        resolved = service.repository.resolve_case_number("2026-鉴-001")
        assert resolved["resolution"] == "alias"
        assert resolved["case"]["id"] == forensic_case["id"]
        direct = service.repository.resolve_case_number("CASE-A1")
        assert direct["resolution"] == "direct"
        actions = {
            row[0] for row in connection.execute(
                "SELECT action FROM audit_events WHERE resource_type='supplement_package'"
            ).fetchall()
        }
        assert {"supplement.registered", "supplement.confirmed"} <= actions
