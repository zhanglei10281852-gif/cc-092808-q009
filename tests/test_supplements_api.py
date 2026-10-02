from __future__ import annotations


def _make_case(client, headers, suffix: str, agency_id: int) -> dict:
    response = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"API-CASE-{suffix}", "case_name": "伤情重新鉴定", "discipline": "法医临床",
        "entrusted_matter": "损伤程度鉴定", "agency_id": agency_id, "case_source": "委托",
        "accepted_on": "2026-09-15", "passport": {"commission_document": f"WS-{suffix}"}, "created_by": "登记员",
    })
    assert response.status_code == 201, response.text
    case_id = response.json()["id"]
    accepted = client.post(f"/api/forensics/cases/{case_id}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "手续齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    return accepted.json()


def test_supplement_http_flow_and_replay(client, admin):
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "API-ORG-1", "agency_name": "区公安分局", "jurisdiction_code": "CN", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text
    forensic_case = _make_case(client, headers, "1", agency.json()["id"])
    payload = {
        "package_no": "API-PKG-1", "idempotency_key": "api-pkg-key-0001", "agency_id": agency.json()["id"],
        "document_no": "ws-1", "case_no_alias": "API-CASE-1", "seal_nos": ["SEAL-API-1"],
        "notes": "补送对照样本", "created_by": "登记员",
    }
    registered = client.post("/api/forensics/supplements", headers=headers, json=payload)
    assert registered.status_code == 201, registered.text
    package = registered.json()["package"]
    assert package["status"] == "pending"
    assert package["candidates"][0]["case"]["id"] == forensic_case["id"]
    assert {item["type"] for item in package["candidates"][0]["evidence"]} >= {"document_no", "case_no_alias"}
    replay = client.post("/api/forensics/supplements", headers=headers, json=payload)
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["package"]["id"] == package["id"]
    confirmed = client.post(f"/api/forensics/supplements/{package['id']}/confirm", headers=headers, json={
        "case_id": forensic_case["id"], "reason": "", "expected_version": 1, "actor": "登记员",
    })
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "confirmed"
    item = client.post(f"/api/forensics/supplements/{package['id']}/items", headers=headers, json={
        "specimen_no": "API-SP-NEW", "received_year": 2026, "initial_quantity": 2,
        "packaging": "独立封装", "created_by": "登记员",
    })
    assert item.status_code == 201, item.text
    assert item.json()["specimen"]["case_id"] == forensic_case["id"]
    detail = client.get(f"/api/forensics/supplements/{package['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["items"][0]["specimen_no"] == "API-SP-NEW"
    listed = client.get("/api/forensics/supplements?status=confirmed", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    resolved = client.get("/api/forensics/cases/resolve/API-CASE-1", headers=headers)
    assert resolved.status_code == 200
    assert resolved.json()["resolution"] == "direct"


def test_merge_http_flow_and_old_number_resolution(client, admin):
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "API-ORG-2", "agency_name": "市检察院", "jurisdiction_code": "CN", "restrictions": {},
    })
    target = _make_case(client, headers, "2A", agency.json()["id"])
    source = _make_case(client, headers, "2B", agency.json()["id"])
    preview = client.post("/api/forensics/case-merges", headers=headers, json={
        "source_case_id": source["id"], "target_case_id": target["id"],
        "reason": "同一鉴定事项误建两案", "actor": "系统管理员",
    })
    assert preview.status_code == 201, preview.text
    merge = preview.json()
    assert merge["plan"]["field_options"]["passport"]["differ"] is True
    assert merge["plan"]["field_options"]["case_name"]["differ"] is False
    executed = client.post(f"/api/forensics/case-merges/{merge['id']}/execute", headers=headers, json={
        "field_decisions": {"entrusted_matter": "target"}, "expected_version": 1, "actor": "系统管理员",
    })
    assert executed.status_code == 200, executed.text
    assert executed.json()["status"] == "executed"
    resolved = client.get(f"/api/forensics/cases/resolve/{source['case_no']}", headers=headers)
    assert resolved.status_code == 200
    assert resolved.json()["resolution"] == "merged"
    assert resolved.json()["merged_into"]["case_no"] == target["case_no"]
    source_detail = client.get(f"/api/forensics/cases/{source['id']}", headers=headers)
    assert source_detail.json()["merged_into"]["case_id"] == target["id"]
    target_detail = client.get(f"/api/forensics/cases/{target['id']}", headers=headers)
    assert target_detail.json()["merged_from"][0]["source_case_no"] == source["case_no"]
    merges = client.get("/api/forensics/case-merges?status=executed", headers=headers)
    assert merges.json()["total"] == 1
    audits = client.get("/api/audit?resource_type=case_merge", headers=headers)
    assert audits.status_code == 200
    actions = {row["action"] for row in audits.json()["data"]}
    assert {"case_merge.previewed", "case_merge.executed"} <= actions


def test_supplement_permission_denied_for_readonly_role(client, admin):
    headers = admin["headers"]
    department = client.post("/api/users", headers=headers, json={
        "username": "auditor1", "password": "Auditor!2345", "display_name": "审计员",
        "role_codes": ["auditor"],
    })
    assert department.status_code in {200, 201}, department.text
    login = client.post("/api/auth/login", json={
        "username": "auditor1", "password": "Auditor!2345", "client_label": "tests",
    })
    assert login.status_code == 200, login.text
    readonly = {"Authorization": f"Bearer {login.json()['token']}"}
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "API-ORG-3", "agency_name": "海关缉私局", "jurisdiction_code": "CN", "restrictions": {},
    })
    denied = client.post("/api/forensics/supplements", headers=readonly, json={
        "package_no": "API-PKG-3", "idempotency_key": "api-pkg-key-0003", "agency_id": agency.json()["id"],
        "document_no": "", "case_no_alias": "", "seal_nos": [], "notes": "", "created_by": "审计员",
    })
    assert denied.status_code == 403
    merge_denied = client.post("/api/forensics/case-merges", headers=readonly, json={
        "source_case_id": 1, "target_case_id": 2, "reason": "无权限尝试", "actor": "审计员",
    })
    assert merge_denied.status_code == 403
