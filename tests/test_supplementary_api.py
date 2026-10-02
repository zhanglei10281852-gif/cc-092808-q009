from __future__ import annotations


def _create_accepted_case(client, headers, suffix: str, document: str) -> dict:
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": f"API-{suffix}", "agency_name": "区公安分局", "jurisdiction_code": "CN",
        "contact_address": "司法路 12 号", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text
    forensic_case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"API-CASE-{suffix}", "case_name": "痕迹比对鉴定", "discipline": "痕迹物证",
        "entrusted_matter": "痕迹同一认定", "agency_id": agency.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-20", "passport": {"commission_document": document}, "created_by": "登记员",
    })
    assert forensic_case.status_code == 201, forensic_case.text
    accepted = client.post(f"/api/forensics/cases/{forensic_case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "手续齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    return accepted.json()


def test_supplementary_http_flow_with_audit_trail(client, admin):
    headers = admin["headers"]
    forensic_case = _create_accepted_case(client, headers, "S1", "司鉴〔2026〕101号")
    payload = {
        "package_no": "PKG-API-S1", "agency_id": forensic_case["agency_id"],
        "commission_document": "司鉴(2026)101号", "case_number_aliases": ["api-case-s1"],
        "reference_seals": [],
        "items": [{"specimen_no": "API-SP-S1", "seal_no": "SEAL-API-S1", "quantity": 3,
                   "received_year": 2026, "packaging": "独立封袋"}],
        "created_by": "登记员", "idempotency_key": "api-pkg-key-s1",
    }
    submitted = client.post("/api/forensics/supplementary-packages", headers=headers, json=payload)
    assert submitted.status_code == 201, submitted.text
    body = submitted.json()
    assert body["status"] == "pending"
    assert body["candidates"][0]["case_no"] == forensic_case["case_no"]
    assert {entry["kind"] for entry in body["candidates"][0]["evidence"]} >= {"commission_document", "alias"}
    replay = client.post("/api/forensics/supplementary-packages", headers=headers, json=payload)
    assert replay.status_code == 201
    assert replay.json() == body
    confirmed = client.post(
        f"/api/forensics/supplementary-packages/{body['id']}/confirm", headers=headers,
        json={"case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员"},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "received"
    specimen_id = confirmed.json()["items"][0]["specimen_id"]
    specimen = client.get(f"/api/forensics/specimens/{specimen_id}", headers=headers)
    assert specimen.json()["case_id"] == forensic_case["id"]
    assert specimen.json()["seal_no"] == "SEAL-API-S1"
    detail = client.get(f"/api/forensics/supplementary-packages/{body['id']}", headers=headers)
    assert [event["event_type"] for event in detail.json()["events"]] == ["submitted", "received"]
    listing = client.get("/api/forensics/supplementary-packages?status=received", headers=headers)
    assert listing.json()["total"] == 1


def test_report_then_supplementary_conflict_resolution_http(client, admin):
    headers = admin["headers"]
    forensic_case = _create_accepted_case(client, headers, "S2", "司鉴〔2026〕102号")
    report = client.post(f"/api/forensics/cases/{forensic_case['id']}/reports", headers=headers, json={
        "report_no": "REP-API-S2", "report_kind": "鉴定意见书", "summary": "已送达", "issued_by": "授权签字人",
    })
    assert report.status_code == 201, report.text
    submitted = client.post("/api/forensics/supplementary-packages", headers=headers, json={
        "package_no": "PKG-API-S2", "agency_id": forensic_case["agency_id"],
        "commission_document": "司鉴〔2026〕102号", "case_number_aliases": [], "reference_seals": [],
        "items": [{"specimen_no": "API-SP-S2", "seal_no": "", "quantity": 2,
                   "received_year": 2026, "packaging": ""}],
        "created_by": "登记员", "idempotency_key": "api-pkg-key-s2",
    })
    assert submitted.status_code == 201
    package = submitted.json()
    confirmed = client.post(
        f"/api/forensics/supplementary-packages/{package['id']}/confirm", headers=headers,
        json={"case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "conflict"
    assert confirmed.json()["conflicts"][0]["kind"] == "case_issued"
    resolved = client.post(
        f"/api/forensics/supplementary-packages/{package['id']}/resolve-conflict", headers=headers,
        json={"decision": "receive", "reason": "委托方补充对照样本，经质量负责人批准接收",
              "expected_version": 2, "actor": "质量负责人"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "received"
    case_detail = client.get(f"/api/forensics/cases/{forensic_case['id']}", headers=headers)
    assert case_detail.json()["reports"][0]["report_no"] == "REP-API-S2"
    assert any(event["event_type"] == "supplementary_received" for event in case_detail.json()["events"])


def test_case_merge_http_flow_and_number_resolution(client, admin):
    headers = admin["headers"]
    source = _create_accepted_case(client, headers, "S3A", "司鉴〔2026〕103号")
    target = _create_accepted_case(client, headers, "S3B", "司鉴〔2026〕104号")
    preview = client.post("/api/forensics/case-merges/previews", headers=headers, json={
        "source_case_id": source["id"], "target_case_id": target["id"],
        "field_resolutions": {"case_name": "source"}, "created_by": "管理员",
    })
    assert preview.status_code == 201, preview.text
    merge = preview.json()
    assert merge["plan"]["blocking_issues"] == []
    executed = client.post(f"/api/forensics/case-merges/{merge['id']}/execute", headers=headers, json={
        "actor": "管理员",
    })
    assert executed.status_code == 200, executed.text
    assert executed.json()["status"] == "executed"
    assert executed.json()["target_case"]["id"] == target["id"]
    resolved = client.get(f"/api/forensics/cases/resolve/{source['case_no']}", headers=headers)
    assert resolved.status_code == 200
    assert resolved.json()["merged"] is True
    assert resolved.json()["canonical_case"]["case_no"] == target["case_no"]
    old_case = client.get(f"/api/forensics/cases/{source['id']}", headers=headers)
    assert old_case.json()["merge"]["target_case_no"] == target["case_no"]
    merges = client.get(f"/api/forensics/case-merges?case_id={target['id']}", headers=headers)
    assert merges.json()["total"] == 1


def test_merge_requires_admin_permission(client, admin):
    created = client.post("/api/users", headers=admin["headers"], json={
        "username": "clerk.merge", "password": "Clerk!23456", "display_name": "登记员",
        "role_codes": ["registrar"],
    })
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={
        "username": "clerk.merge", "password": "Clerk!23456", "client_label": "tests",
    })
    clerk_headers = {"Authorization": f"Bearer {login.json()['token']}"}
    source = _create_accepted_case(client, admin["headers"], "S4A", "司鉴〔2026〕105号")
    target = _create_accepted_case(client, admin["headers"], "S4B", "司鉴〔2026〕106号")
    denied = client.post("/api/forensics/case-merges/previews", headers=clerk_headers, json={
        "source_case_id": source["id"], "target_case_id": target["id"],
        "field_resolutions": {}, "created_by": "登记员",
    })
    assert denied.status_code == 403
    anonymous = client.post("/api/forensics/case-merges/previews", json={
        "source_case_id": source["id"], "target_case_id": target["id"],
        "field_resolutions": {}, "created_by": "登记员",
    })
    assert anonymous.status_code == 401
    visible = client.get("/api/forensics/case-merges", headers=clerk_headers)
    assert visible.status_code == 200
