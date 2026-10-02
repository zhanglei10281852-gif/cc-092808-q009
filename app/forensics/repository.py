from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from app.core.errors import NotFoundError


JSON_COLUMNS = {
    "case_profile_json": "passport",
    "contact_json": "restrictions",
    "detail_json": "detail",
    "payload_json": "payload",
    "seal_nos_json": "seal_nos",
    "evidence_json": "evidence",
    "conflict_json": "conflict",
    "plan_json": "plan",
    "decisions_json": "decisions",
    "result_json": "result",
}


def case_closed(case: dict[str, Any]) -> bool:
    """已退出保存或已签发报告的案件视为关闭签发。"""
    return case.get("status") == "retired" or bool(case.get("report_signed_at"))


def record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for column, target in JSON_COLUMNS.items():
        if column in data:
            raw = data.pop(column)
            try:
                data[target] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data[target] = {}
    return data


def records(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [record(row) or {} for row in rows]


class ForensicRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def require_agency(self, agency_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM submitting_agencies WHERE id=?", (agency_id,)).fetchone())
        if item is None:
            raise NotFoundError("来源记录不存在")
        return item

    def require_forensic_case(self, case_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM forensic_cases WHERE id=?", (case_id,)).fetchone())
        if item is None:
            raise NotFoundError("鉴定案件不存在")
        return item

    def forensic_case_by_number(self, case_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM forensic_cases WHERE case_no=?", (case_no,)).fetchone())

    def forensic_case_detail(self, case_id: int) -> dict[str, Any]:
        item = self.require_forensic_case(case_id)
        if item.get("agency_id"):
            item["source"] = self.require_agency(int(item["agency_id"]))
        item["lots"] = records(self.connection.execute(
            "SELECT * FROM specimens WHERE case_id=? ORDER BY created_at,specimen_no", (case_id,)
        ).fetchall())
        item["events"] = records(self.connection.execute(
            "SELECT * FROM case_events WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall())
        item["aliases"] = records(self.connection.execute(
            "SELECT * FROM case_aliases WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall())
        item["merged_into"] = self._final_merge_target(item)
        item["merged_from"] = records(self.connection.execute(
            "SELECT m.id,m.merge_no,m.source_case_id,c.case_no AS source_case_no,m.executed_at FROM case_merges m "
            "JOIN forensic_cases c ON c.id=m.source_case_id WHERE m.target_case_id=? AND m.status='executed' ORDER BY m.id",
            (case_id,),
        ).fetchall())
        return item

    def _final_merge_target(self, case: dict[str, Any]) -> dict[str, Any] | None:
        seen: set[int] = set()
        current = case
        while current.get("merged_into_case_id") and int(current["id"]) not in seen and len(seen) < 10:
            seen.add(int(current["id"]))
            current = self.require_forensic_case(int(current["merged_into_case_id"]))
        if int(current["id"]) == int(case["id"]):
            return None
        return {
            "case_id": current["id"],
            "case_no": current["case_no"],
            "case_name": current["case_name"],
            "status": current["status"],
        }

    def resolve_case_number(self, case_no: str) -> dict[str, Any]:
        normalized = case_no.strip().upper()
        case = record(self.connection.execute("SELECT * FROM forensic_cases WHERE case_no=?", (normalized,)).fetchone())
        via = "direct"
        if case is None:
            alias = record(self.connection.execute("SELECT * FROM case_aliases WHERE alias_no=?", (normalized,)).fetchone())
            if alias is None:
                raise NotFoundError("无法解析该案件编号")
            case = self.require_forensic_case(int(alias["case_id"]))
            via = "alias"
        detail = self.forensic_case_detail(int(case["id"]))
        resolution = via
        if case.get("merged_into_case_id"):
            resolution = "merged" if via == "direct" else "merged_alias"
        return {"query": case_no, "resolution": resolution, "case": detail, "merged_into": detail.get("merged_into")}

    def matching_cases(self) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM forensic_cases WHERE merged_into_case_id IS NULL ORDER BY id"
        ).fetchall())

    def list_forensic_cases(self, *, status: str | None, crop: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status=?")
            params.append(status)
        if crop:
            where.append("discipline LIKE ?")
            params.append(f"%{crop.strip()}%")
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM forensic_cases{clause}", params).fetchone()[0])
        params.extend([limit, offset])
        rows = self.connection.execute(
            f"SELECT * FROM forensic_cases{clause} ORDER BY accepted_on DESC,case_no LIMIT ? OFFSET ?", params
        ).fetchall()
        return records(rows), total

    def require_location(self, location_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM storage_locations WHERE id=?", (location_id,)).fetchone())
        if item is None:
            raise NotFoundError("库位不存在")
        return item

    def location_usage(self, location_id: int) -> float:
        row = self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE location_id=? AND removed_at IS NULL",
            (location_id,),
        ).fetchone()
        return float(row[0])

    def location_detail(self, location_id: int) -> dict[str, Any]:
        item = self.require_location(location_id)
        item["used_grams"] = self.location_usage(location_id)
        item["available_grams"] = round(float(item["capacity_units"]) - item["used_grams"], 6)
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,l.specimen_no FROM specimen_placements p JOIN specimens l ON l.id=p.specimen_id "
            "WHERE p.location_id=? AND p.removed_at IS NULL ORDER BY p.container_code", (location_id,)
        ).fetchall())
        return item

    def require_specimen(self, specimen_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimens WHERE id=?", (specimen_id,)).fetchone())
        if item is None:
            raise NotFoundError("检材不存在")
        return item

    def active_holds(self, specimen_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? AND released_at IS NULL ORDER BY id", (specimen_id,)
        ).fetchall())

    def specimen_detail(self, specimen_id: int) -> dict[str, Any]:
        item = self.require_specimen(specimen_id)
        item["forensic_case"] = self.require_forensic_case(int(item["case_id"]))
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,s.location_code FROM specimen_placements p JOIN storage_locations s ON s.id=p.location_id "
            "WHERE p.specimen_id=? ORDER BY p.id", (specimen_id,)
        ).fetchall())
        item["movements"] = records(self.connection.execute(
            "SELECT * FROM custody_events WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["holds"] = records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["latest_examination"] = record(self.connection.execute(
            "SELECT * FROM examinations WHERE specimen_id=? AND status='completed' ORDER BY completed_at DESC,id DESC LIMIT 1",
            (specimen_id,),
        ).fetchone())
        return item

    def require_placement(self, placement_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimen_placements WHERE id=?", (placement_id,)).fetchone())
        if item is None:
            raise NotFoundError("容器摆放记录不存在")
        return item

    def custody_event_by_key(self, key: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM custody_events WHERE idempotency_key=?", (key,)).fetchone())

    def require_protocol(self, protocol_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examination_protocols WHERE id=?", (protocol_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验规程不存在")
        return item

    def protocol_latest(self, code: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM examination_protocols WHERE protocol_code=? ORDER BY version DESC LIMIT 1", (code,)
        ).fetchone())

    def require_examination(self, examination_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examinations WHERE id=?", (examination_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验任务不存在")
        return item

    def examination_detail(self, examination_id: int) -> dict[str, Any]:
        item = self.require_examination(examination_id)
        item["specimen"] = self.require_specimen(int(item["specimen_id"]))
        item["protocol"] = self.require_protocol(int(item["protocol_id"]))
        item["counts"] = records(self.connection.execute(
            "SELECT * FROM examination_observations WHERE examination_id=? ORDER BY checkpoint_no,sequence_no", (examination_id,)
        ).fetchall())
        return item

    def require_policy(self, policy_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM review_policies WHERE id=?", (policy_id,)).fetchone())
        if item is None:
            raise NotFoundError("复核策略不存在")
        return item

    def applicable_policy(self, discipline: str, risk_level: str, on_date: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM review_policies WHERE discipline=? AND risk_level=? AND effective_from<=? "
            "AND (effective_to IS NULL OR effective_to>=?) ORDER BY version DESC LIMIT 1",
            (discipline, risk_level, on_date, on_date),
        ).fetchone())

    def require_alert(self, alert_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM quality_alerts WHERE id=?", (alert_id,)).fetchone())
        if item is None:
            raise NotFoundError("质量告警不存在")
        return item

    def require_release(self, request_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM release_requests WHERE id=?", (request_id,)).fetchone())
        if item is None:
            raise NotFoundError("领用申请不存在")
        return item

    def release_detail(self, request_id: int) -> dict[str, Any]:
        item = self.require_release(request_id)
        item["items"] = records(self.connection.execute(
            "SELECT i.*,a.case_no,a.discipline FROM release_items i "
            "JOIN forensic_cases a ON a.id=i.case_id WHERE i.request_id=? ORDER BY i.id", (request_id,)
        ).fetchall())
        return item

    def require_package(self, package_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM supplement_packages WHERE id=?", (package_id,)).fetchone())
        if item is None:
            raise NotFoundError("补送包不存在")
        return item

    def package_detail(self, package_id: int) -> dict[str, Any]:
        item = self.require_package(package_id)
        item["agency"] = self.require_agency(int(item["agency_id"]))
        candidates = records(self.connection.execute(
            "SELECT * FROM supplement_candidates WHERE package_id=? ORDER BY score DESC,id", (package_id,)
        ).fetchall())
        for candidate in candidates:
            forensic_case = self.require_forensic_case(int(candidate["case_id"]))
            candidate["case"] = {
                "id": forensic_case["id"],
                "case_no": forensic_case["case_no"],
                "case_name": forensic_case["case_name"],
                "discipline": forensic_case["discipline"],
                "status": forensic_case["status"],
                "closed": case_closed(forensic_case),
            }
        item["candidates"] = candidates
        item["items"] = records(self.connection.execute(
            "SELECT i.*,s.specimen_no,s.status AS specimen_status FROM supplement_package_items i "
            "JOIN specimens s ON s.id=i.specimen_id WHERE i.package_id=? ORDER BY i.id", (package_id,)
        ).fetchall())
        item["matched_case"] = None
        if item.get("matched_case_id"):
            matched = self.require_forensic_case(int(item["matched_case_id"]))
            item["matched_case"] = {
                "id": matched["id"],
                "case_no": matched["case_no"],
                "case_name": matched["case_name"],
                "status": matched["status"],
                "closed": case_closed(matched),
            }
        item["seal_conflicts"] = [
            row for row in self.seal_owners(item["seal_nos"])
            if item.get("matched_case_id") is None or int(row["case_id"]) != int(item["matched_case_id"])
        ]
        return item

    def list_packages(self, *, status: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        clause = ""
        params: list[Any] = []
        if status:
            clause = " WHERE status=?"
            params.append(status)
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM supplement_packages{clause}", params).fetchone()[0])
        rows = self.connection.execute(
            f"SELECT * FROM supplement_packages{clause} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset)
        ).fetchall()
        return records(rows), total

    def seal_owners(self, seal_nos: list[str]) -> list[dict[str, Any]]:
        if not seal_nos:
            return []
        placeholders = ",".join("?" for _ in seal_nos)
        return records(self.connection.execute(
            f"SELECT r.*,c.case_no FROM seal_registry r JOIN forensic_cases c ON c.id=r.case_id "
            f"WHERE r.seal_no IN ({placeholders}) ORDER BY r.seal_no,r.id",
            tuple(seal_nos),
        ).fetchall())

    def aliases_for_case(self, case_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM case_aliases WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall())

    def require_merge(self, merge_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM case_merges WHERE id=?", (merge_id,)).fetchone())
        if item is None:
            raise NotFoundError("案件归并记录不存在")
        return item

    def merge_detail(self, merge_id: int) -> dict[str, Any]:
        item = self.require_merge(merge_id)
        for key in ("source_case_id", "target_case_id"):
            forensic_case = self.require_forensic_case(int(item[key]))
            item["source_case" if key == "source_case_id" else "target_case"] = {
                "id": forensic_case["id"],
                "case_no": forensic_case["case_no"],
                "case_name": forensic_case["case_name"],
                "discipline": forensic_case["discipline"],
                "status": forensic_case["status"],
                "merged_into_case_id": forensic_case.get("merged_into_case_id"),
            }
        return item

    def list_merges(self, *, status: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        clause = ""
        params: list[Any] = []
        if status:
            clause = " WHERE status=?"
            params.append(status)
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM case_merges{clause}", params).fetchone()[0])
        rows = self.connection.execute(
            f"SELECT * FROM case_merges{clause} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset)
        ).fetchall()
        return records(rows), total

    def active_merge_for_source(self, source_case_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM case_merges WHERE source_case_id=? AND status IN ('previewed','executed')",
            (source_case_id,),
        ).fetchone())

    def count_table(self, table: str) -> int:
        allowed = {
            "forensic_cases", "specimens", "storage_locations", "examinations",
            "review_schedules", "quality_alerts", "release_requests",
            "supplement_packages", "case_merges",
        }
        if table not in allowed:
            raise ValueError("不允许统计该数据表")
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
