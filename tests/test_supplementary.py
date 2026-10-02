from __future__ import annotations

import pytest

from app.core.errors import ConflictError, ValidationError
from app.database import transaction
from app.forensics.service import ForensicService


def create_case(service: ForensicService, suffix: str, *, document: str = "", accept: bool = True) -> dict:
    agency = service.forensic_cases.create_agency({
        "agency_code": f"ORG-{suffix}", "agency_name": "市公安局物证中心", "jurisdiction_code": "CN",
        "contact_address": "司法路 8 号", "licensed_on": "2026-01-01", "accreditation_no": None,
        "restrictions": {},
    })
    forensic_case = service.forensic_cases.create_forensic_case({
        "case_no": f"CASE-{suffix}", "case_name": "身份关系鉴定", "discipline": "法医物证",
        "entrusted_matter": "亲缘关系鉴定", "agency_id": agency["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {"commission_document": document} if document else {},
        "created_by": "登记员",
    })
    if not accept:
        return forensic_case
    return service.forensic_cases.transition(forensic_case["id"], {
        "target_status": "accepted", "reason": "资料齐全", "expected_version": 1, "actor": "审核员",
    })


def create_sealed_specimen(service: ForensicService, case: dict, specimen_no: str, seal_no: str) -> dict:
    return service.custody.create_specimen({
        "specimen_no": specimen_no, "case_id": case["id"], "parent_specimen_id": None,
        "received_year": 2026, "initial_quantity": 100, "integrity_percent": 100,
        "packaging": "防拆封袋", "sealed_on": "2026-09-02", "seal_no": seal_no, "created_by": "登记员",
    })


def submit_package(service: ForensicService, case: dict | None, suffix: str, **overrides) -> dict:
    payload = {
        "package_no": f"PKG-{suffix}",
        "agency_id": case["agency_id"] if case else None,
        "commission_document": "",
        "case_number_aliases": [],
        "reference_seals": [],
        "items": [{
            "specimen_no": f"SP-NEW-{suffix}", "seal_no": f"SEAL-NEW-{suffix}", "quantity": 20,
            "received_year": 2026, "packaging": "独立封袋",
        }],
        "created_by": "登记员",
        "idempotency_key": f"pkg-key-{suffix}",
    }
    payload.update(overrides)
    return service.supplementary.submit_package(payload)


def test_candidates_carry_evidence_and_confirm_receives(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_case(service, "C1", document="司鉴〔2026〕88号")
        create_sealed_specimen(service, forensic_case, "SP-C1", "SEAL-C1")
        package = submit_package(
            service, forensic_case, "C1",
            commission_document="司鉴[2026]88 号",
            case_number_aliases=["case-c1", "司鉴2026-88"],
            reference_seals=["seal-c1"],
        )
        assert package["status"] == "pending"
        assert len(package["candidates"]) == 1
        candidate = package["candidates"][0]
        assert candidate["case_id"] == forensic_case["id"]
        kinds = {entry["kind"] for entry in candidate["evidence"]}
        assert kinds == {"agency", "commission_document", "alias", "seal"}
        confirmed = service.supplementary.confirm(package["id"], {
            "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "received"
        assert confirmed["confirmed_case"]["id"] == forensic_case["id"]
        received_item = confirmed["items"][0]
        assert received_item["specimen_id"] is not None
        specimen = service.repository.require_specimen(received_item["specimen_id"])
        assert specimen["case_id"] == forensic_case["id"]
        assert specimen["seal_no"] == "SEAL-NEW-C1"
        detail = service.repository.forensic_case_detail(forensic_case["id"])
        assert any(alias["alias"] == "司鉴2026-88" for alias in detail["aliases"])
        assert any(event["event_type"] == "supplementary_received" for event in detail["events"])
        event_types = [event["event_type"] for event in confirmed["events"]]
        assert event_types == ["submitted", "received"]
        by_number = service.merges.resolve_number("casec1")
        assert by_number["found"] and by_number["via"] == "case_no_normalized"
        by_alias = service.merges.resolve_number("司鉴 2026 88")
        assert by_alias["found"] and by_alias["via"] == "alias"
        assert by_alias["case"]["id"] == forensic_case["id"]


def test_agency_only_match_is_quarantined_and_needs_reason(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_case(service, "C2", document="司鉴〔2026〕99号")
        package = submit_package(service, forensic_case, "C2")
        assert package["status"] == "quarantined"
        assert package["candidates"] == []
        assert [event["event_type"] for event in package["events"]] == ["submitted", "quarantined"]
        with pytest.raises(ValidationError):
            service.supplementary.confirm(package["id"], {
                "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
            })
        confirmed = service.supplementary.confirm(package["id"], {
            "case_id": forensic_case["id"], "reason": "电话核实委托单位确为同一鉴定事项",
            "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "received"


def test_multiple_candidates_stay_quarantined(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        create_case(service, "C3A", document="司鉴〔2026〕77号")
        create_case(service, "C3B", document="司鉴(2026)77号")
        package = submit_package(service, None, "C3", commission_document="司鉴2026-77号")
        assert package["status"] == "quarantined"
        assert len(package["candidates"]) == 2
        assert package["items"][0]["specimen_id"] is None


def test_resubmit_returns_first_result(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_case(service, "C4", document="司鉴〔2026〕66号")
        payload = {
            "package_no": "PKG-C4", "agency_id": forensic_case["agency_id"],
            "commission_document": "司鉴〔2026〕66号", "case_number_aliases": [], "reference_seals": [],
            "items": [{"specimen_no": "SP-NEW-C4", "seal_no": "", "quantity": 5,
                       "received_year": 2026, "packaging": ""}],
            "created_by": "登记员", "idempotency_key": "pkg-key-C4",
        }
        first = service.supplementary.submit_package(payload)
        assert first["status"] == "pending"
        service.supplementary.confirm(first["id"], {
            "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        replay = service.supplementary.submit_package(payload)
        assert replay["id"] == first["id"]
        assert replay["status"] == "pending"
        assert replay["items"][0]["specimen_id"] is None
        changed = dict(payload, commission_document="司鉴〔2026〕67号")
        with pytest.raises(ConflictError):
            service.supplementary.submit_package(changed)


def test_seal_occupied_by_other_case_goes_to_conflict_then_resolved(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        holder = create_case(service, "C5A", document="司鉴〔2026〕51号")
        create_sealed_specimen(service, holder, "SP-C5A", "SEAL-TAKEN")
        target = create_case(service, "C5B", document="司鉴〔2026〕52号")
        package = submit_package(
            service, target, "C5",
            commission_document="司鉴〔2026〕52号",
            items=[{"specimen_no": "SP-NEW-C5", "seal_no": "seal-taken", "quantity": 10,
                    "received_year": 2026, "packaging": ""}],
        )
        assert package["status"] == "pending"
        confirmed = service.supplementary.confirm(package["id"], {
            "case_id": target["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "conflict"
        assert confirmed["conflicts"][0]["kind"] == "seal_occupied"
        assert confirmed["conflicts"][0]["holder_case_no"] == holder["case_no"]
        with pytest.raises(ConflictError):
            service.supplementary.confirm(package["id"], {
                "case_id": target["id"], "reason": "", "expected_version": 2, "actor": "登记员",
            })
        rejected = service.supplementary.resolve_conflict(package["id"], {
            "decision": "reject", "reason": "封识与他案重复，退回委托方核实",
            "expected_version": 2, "actor": "质量负责人",
        })
        assert rejected["status"] == "rejected"
        remaining = connection.execute(
            "SELECT COUNT(*) FROM specimens WHERE specimen_no='SP-NEW-C5'"
        ).fetchone()[0]
        assert remaining == 0


def test_conflict_receive_override_creates_specimen_with_audit(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        holder = create_case(service, "C6A", document="司鉴〔2026〕61号")
        create_sealed_specimen(service, holder, "SP-C6A", "SEAL-DUP")
        target = create_case(service, "C6B", document="司鉴〔2026〕62号")
        package = submit_package(
            service, target, "C6",
            commission_document="司鉴〔2026〕62号",
            items=[{"specimen_no": "SP-NEW-C6", "seal_no": "SEAL-DUP", "quantity": 10,
                    "received_year": 2026, "packaging": ""}],
        )
        service.supplementary.confirm(package["id"], {
            "case_id": target["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        resolved = service.supplementary.resolve_conflict(package["id"], {
            "decision": "receive", "reason": "委托方书面说明封识号笔误，实物封识唯一",
            "expected_version": 2, "actor": "质量负责人",
        })
        assert resolved["status"] == "received"
        specimen = service.repository.require_specimen(resolved["items"][0]["specimen_id"])
        assert specimen["case_id"] == target["id"]
        event_types = [event["event_type"] for event in resolved["events"]]
        assert event_types == ["submitted", "conflict_raised", "received", "conflict_resolved"]
        resolved_event = resolved["events"][-1]
        assert resolved_event["detail"]["overridden_conflicts"][0]["kind"] == "seal_occupied"


def test_closed_or_issued_case_requires_conflict_handling(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        closed = create_case(service, "C7A", document="司鉴〔2026〕71号")
        service.forensic_cases.transition(closed["id"], {
            "target_status": "retired", "reason": "鉴定完成已结案", "expected_version": 2, "actor": "审核员",
        })
        package = submit_package(service, closed, "C7A", commission_document="司鉴〔2026〕71号")
        confirmed = service.supplementary.confirm(package["id"], {
            "case_id": closed["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert confirmed["status"] == "conflict"
        assert confirmed["conflicts"][0]["kind"] == "case_closed"

        issued = create_case(service, "C7B", document="司鉴〔2026〕72号")
        service.forensic_cases.issue_report(issued["id"], {
            "report_no": "REP-C7B", "report_kind": "鉴定意见书", "summary": "已送达", "issued_by": "授权签字人",
        })
        package_b = submit_package(service, issued, "C7B", commission_document="司鉴〔2026〕72号")
        confirmed_b = service.supplementary.confirm(package_b["id"], {
            "case_id": issued["id"], "reason": "", "expected_version": 1, "actor": "登记员",
        })
        assert confirmed_b["status"] == "conflict"
        assert confirmed_b["conflicts"][0]["kind"] == "case_issued"
        assert confirmed_b["conflicts"][0]["report_nos"] == ["REP-C7B"]


def test_report_issuance_rules(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_case(service, "C8", document="司鉴〔2026〕81号")
        report = service.forensic_cases.issue_report(forensic_case["id"], {
            "report_no": "REP-C8", "report_kind": "鉴定意见书", "summary": "", "issued_by": "授权签字人",
        })
        assert report["report_no"] == "REP-C8"
        with pytest.raises(ConflictError):
            service.forensic_cases.issue_report(forensic_case["id"], {
                "report_no": "REP-C8", "report_kind": "检验报告", "summary": "", "issued_by": "授权签字人",
            })
        draft = create_case(service, "C8D", accept=False)
        with pytest.raises(ConflictError):
            service.forensic_cases.issue_report(draft["id"], {
                "report_no": "REP-C8D", "report_kind": "鉴定意见书", "summary": "", "issued_by": "授权签字人",
            })
