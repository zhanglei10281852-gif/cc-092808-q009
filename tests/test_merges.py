from __future__ import annotations

import pytest

from app.core.errors import ConflictError, ValidationError
from app.database import transaction
from app.forensics.service import ForensicService
from tests.test_supplementary import create_case, create_sealed_specimen


def build_source_with_history(service: ForensicService, suffix: str) -> tuple[dict, dict]:
    forensic_case = create_case(service, suffix, document=f"司鉴〔2026〕{suffix}号")
    location = service.custody.create_location({
        "location_code": f"VAULT-{suffix}", "facility": "检材保管室", "room": "冷藏区", "rack": "R1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    specimen = create_sealed_specimen(service, forensic_case, f"SP-{suffix}", f"SEAL-{suffix}")
    service.custody.place_specimen({
        "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 100,
        "container_code": f"BOX-{suffix}", "idempotency_key": f"place-{suffix}-0001", "actor": "保管员",
    })
    return service.repository.require_forensic_case(forensic_case["id"]), service.repository.require_specimen(specimen["id"])


def test_merge_preview_execute_and_old_number_resolution(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source, specimen = build_source_with_history(service, "M1")
        target = create_case(service, "M1T", document="司鉴〔2026〕M1T号")
        custody_before = connection.execute(
            "SELECT id,specimen_id,movement_type,quantity FROM custody_events WHERE specimen_id=? ORDER BY id",
            (specimen["id"],),
        ).fetchall()
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        assert preview["status"] == "preview"
        assert preview["plan"]["blocking_issues"] == []
        assert [item["id"] for item in preview["plan"]["references"]["specimens"]] == [specimen["id"]]
        assert preview["plan"]["references"]["specimen_followers"]["custody_events"] == 1
        assert all(entry["keep"] == "target" for entry in preview["plan"]["field_plan"])
        executed = service.merges.execute(preview["id"], "管理员")
        assert executed["status"] == "executed"
        assert executed["result"]["moved_specimen_ids"] == [specimen["id"]]
        assert executed["result"]["alias_registered"] == source["case_no"]
        moved = service.repository.require_specimen(specimen["id"])
        assert moved["case_id"] == target["id"]
        custody_after = connection.execute(
            "SELECT id,specimen_id,movement_type,quantity FROM custody_events WHERE specimen_id=? ORDER BY id",
            (specimen["id"],),
        ).fetchall()
        assert [tuple(row) for row in custody_after] == [tuple(row) for row in custody_before]
        source_after = service.repository.require_forensic_case(source["id"])
        assert source_after["status"] == "retired"
        assert target["case_no"] in source_after["return_reason"]
        resolved = service.merges.resolve_number(source["case_no"])
        assert resolved["found"] and resolved["merged"] is True
        assert resolved["canonical_case"]["id"] == target["id"]
        source_detail = service.repository.forensic_case_detail(source["id"])
        assert source_detail["merge"]["target_case_id"] == target["id"]
        target_detail = service.repository.forensic_case_detail(target["id"])
        assert any(event["event_type"] == "merged_from" for event in target_detail["events"])
        assert any(alias["alias"] == source["case_no"] for alias in target_detail["aliases"])
        with pytest.raises(ConflictError):
            service.merges.execute(preview["id"], "管理员")


def test_merge_field_resolutions_keep_source_values(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source = create_case(service, "M2", document="司鉴〔2026〕M2号")
        target = create_case(service, "M2T", document="司鉴〔2026〕M2T号")
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {"case_name": "source", "passport": "source", "entrusted_matter": "target"},
            "created_by": "管理员",
        })
        plan = {entry["field"]: entry for entry in preview["plan"]["field_plan"]}
        assert plan["case_name"]["resulting_value"] == source["case_name"]
        assert plan["entrusted_matter"]["resulting_value"] == target["entrusted_matter"]
        executed = service.merges.execute(preview["id"], "管理员")
        target_after = service.repository.require_forensic_case(target["id"])
        assert target_after["case_name"] == source["case_name"]
        assert target_after["passport"] == source["passport"]
        assert target_after["entrusted_matter"] == target["entrusted_matter"]
        changes = {entry["field"]: entry for entry in executed["result"]["field_changes"]}
        assert changes["case_name"]["keep"] == "source"
        assert changes["discipline"]["keep"] == "target"


def test_merge_keeps_reports_and_case_events_immutable(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source, _ = build_source_with_history(service, "M3")
        service.forensic_cases.issue_report(source["id"], {
            "report_no": "REP-M3", "report_kind": "鉴定意见书", "summary": "已送达", "issued_by": "授权签字人",
        })
        target = create_case(service, "M3T", document="司鉴〔2026〕M3T号")
        events_before = connection.execute(
            "SELECT event_type,detail_json FROM case_events WHERE case_id=? ORDER BY id", (source["id"],)
        ).fetchall()
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        assert any("报告" in warning for warning in preview["plan"]["warnings"])
        assert preview["plan"]["references"]["case_reports_stay"][0]["report_no"] == "REP-M3"
        service.merges.execute(preview["id"], "管理员")
        reports = service.repository.case_reports(source["id"])
        assert [report["report_no"] for report in reports] == ["REP-M3"]
        assert service.repository.case_reports(target["id"]) == []
        events_after = connection.execute(
            "SELECT event_type,detail_json FROM case_events WHERE case_id=? ORDER BY id", (source["id"],)
        ).fetchall()
        assert [tuple(row) for row in events_after[: len(events_before)]] == [tuple(row) for row in events_before]
        assert events_after[-1]["event_type"] == "merged_into"


def test_merge_validation_and_blocking(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source = create_case(service, "M4", document="司鉴〔2026〕M4号")
        target = create_case(service, "M4T", document="司鉴〔2026〕M4T号")
        with pytest.raises(ValidationError):
            service.merges.preview({
                "source_case_id": source["id"], "target_case_id": target["id"],
                "field_resolutions": {"case_no": "source"}, "created_by": "管理员",
            })
        same = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": source["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        assert same["plan"]["blocking_issues"]
        with pytest.raises(ConflictError):
            service.merges.execute(same["id"], "管理员")
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        service.merges.execute(preview["id"], "管理员")
        again = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        assert any("已经被归并" in issue for issue in again["plan"]["blocking_issues"])
        cancelled = service.merges.cancel(again["id"], "管理员")
        assert cancelled["status"] == "cancelled"


def test_package_matching_merged_case_points_to_surviving_case(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source = create_case(service, "M6", document="司鉴〔2026〕M6号")
        target = create_case(service, "M6T", document="司鉴〔2026〕M6T号")
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        service.merges.execute(preview["id"], "管理员")
        package = service.supplementary.submit_package({
            "package_no": "PKG-M6", "agency_id": None, "commission_document": "",
            "case_number_aliases": ["case-m6"], "reference_seals": [],
            "items": [{"specimen_no": "SP-NEW-M6", "seal_no": "", "quantity": 5,
                       "received_year": 2026, "packaging": ""}],
            "created_by": "登记员", "idempotency_key": "pkg-key-M6",
        })
        assert package["status"] == "pending"
        assert len(package["candidates"]) == 1
        candidate = package["candidates"][0]
        assert candidate["case_id"] == target["id"]
        assert any(
            entry.get("via_merged_case_no") == source["case_no"] for entry in candidate["evidence"]
        )


def test_merge_moves_release_items_and_confirm_redirects(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        source, _ = build_source_with_history(service, "M5")
        request = service.release.create_request({
            "request_no": "REL-M5", "requester": "法医物证实验室", "purpose": "补充检验取样",
            "items": [{"case_id": source["id"], "quantity": 10}],
        })
        target = create_case(service, "M5T", document="司鉴〔2026〕M5T号")
        preview = service.merges.preview({
            "source_case_id": source["id"], "target_case_id": target["id"],
            "field_resolutions": {}, "created_by": "管理员",
        })
        assert preview["plan"]["references"]["release_items"][0]["request_id"] == request["id"]
        executed = service.merges.execute(preview["id"], "管理员")
        assert executed["result"]["moved_release_item_ids"]
        moved_item = connection.execute("SELECT case_id FROM release_items WHERE request_id=?", (request["id"],)).fetchone()
        assert moved_item["case_id"] == target["id"]
        package = service.supplementary.submit_package({
            "package_no": "PKG-M5", "agency_id": target["agency_id"], "commission_document": "司鉴〔2026〕M5T号",
            "case_number_aliases": [], "reference_seals": [],
            "items": [{"specimen_no": "SP-NEW-M5", "seal_no": "", "quantity": 5,
                       "received_year": 2026, "packaging": ""}],
            "created_by": "登记员", "idempotency_key": "pkg-key-M5",
        })
        with pytest.raises(ConflictError) as excinfo:
            service.supplementary.confirm(package["id"], {
                "case_id": source["id"], "reason": "旧编号补送", "expected_version": 1, "actor": "登记员",
            })
        assert excinfo.value.context["canonical_case_id"] == target["id"]
