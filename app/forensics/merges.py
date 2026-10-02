from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.forensics.identifiers import normalize_identifier
from app.forensics.repository import ForensicRepository, record, records

MERGEABLE_FIELDS = ("case_name", "discipline", "entrusted_matter", "agency_id", "passport")
FIELD_COLUMNS = {
    "case_name": "case_name",
    "discipline": "discipline",
    "entrusted_matter": "entrusted_matter",
    "agency_id": "agency_id",
    "passport": "case_profile_json",
}


class CaseMergeService:
    """误建案件归并：预演引用迁移、逐字段决定保留值、执行后旧编号仍可解析。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    def preview(self, data: dict[str, Any]) -> dict[str, Any]:
        source_id = int(data["source_case_id"])
        target_id = int(data["target_case_id"])
        resolutions = self._validate_resolutions(data.get("field_resolutions", {}))
        source = self.repository.require_forensic_case(source_id)
        target = self.repository.require_forensic_case(target_id)
        blocking = self._blocking_issues(source, target)
        warnings = self._warnings(source, target)
        references = self._references(source_id)
        field_plan = [
            {
                "field": field,
                "keep": resolutions.get(field, "target"),
                "source_value": source.get(field),
                "target_value": target.get(field),
                "resulting_value": source.get(field) if resolutions.get(field) == "source" else target.get(field),
            }
            for field in MERGEABLE_FIELDS
        ]
        timestamp = to_storage(self.clock.now())
        plan = {
            "computed_at": timestamp,
            "references": references,
            "field_plan": field_plan,
            "blocking_issues": blocking,
            "warnings": warnings,
        }
        cursor = self.connection.execute(
            "INSERT INTO case_merges(source_case_id,target_case_id,field_resolutions_json,plan_json,status,"
            "created_by,created_at) VALUES(?,?,?,?,'preview',?,?)",
            (
                source_id, target_id, json.dumps(resolutions, ensure_ascii=False, sort_keys=True),
                json.dumps(plan, ensure_ascii=False, sort_keys=True), data["created_by"], timestamp,
            ),
        )
        return self.repository.merge_detail(int(cursor.lastrowid))

    def execute(self, merge_id: int, actor: str) -> dict[str, Any]:
        merge = self.repository.require_merge(merge_id)
        if merge["status"] != "preview":
            raise ConflictError("归并单已处理，不能重复执行", context={"status": merge["status"]})
        source = self.repository.require_forensic_case(int(merge["source_case_id"]))
        target = self.repository.require_forensic_case(int(merge["target_case_id"]))
        blocking = self._blocking_issues(source, target)
        if blocking:
            raise ConflictError("归并条件已不满足，请重新预演", context={"blocking_issues": blocking})
        timestamp = to_storage(self.clock.now())
        resolutions = merge.get("field_resolutions", {})
        field_changes = self._apply_fields(source, target, resolutions, timestamp)
        moved_specimens = [
            int(row["id"]) for row in self.connection.execute(
                "SELECT id FROM specimens WHERE case_id=? ORDER BY id", (source["id"],)
            ).fetchall()
        ]
        self.connection.execute(
            "UPDATE specimens SET case_id=?,version=version+1,updated_at=? WHERE case_id=?",
            (target["id"], timestamp, source["id"]),
        )
        moved_release_items = [
            int(row["id"]) for row in self.connection.execute(
                "SELECT id FROM release_items WHERE case_id=? ORDER BY id", (source["id"],)
            ).fetchall()
        ]
        self.connection.execute(
            "UPDATE release_items SET case_id=? WHERE case_id=?", (target["id"], source["id"])
        )
        alias_registered = self._register_source_number(source, target, merge_id, actor, timestamp)
        source_status_from = str(source["status"])
        retire_reason = f"已归并至 {target['case_no']}（归并单 #{merge_id}）"
        if source_status_from == "retired" and source.get("return_reason"):
            retire_reason = f"{source['return_reason']}；{retire_reason}"
        self.connection.execute(
            "UPDATE forensic_cases SET status='retired',return_reason=?,version=version+1,updated_at=? WHERE id=?",
            (retire_reason, timestamp, source["id"]),
        )
        self._case_event(int(source["id"]), "merged_into", actor, source_status_from, "retired", {
            "merge_id": merge_id, "target_case_id": target["id"], "target_case_no": target["case_no"],
        })
        self._case_event(int(target["id"]), "merged_from", actor, None, None, {
            "merge_id": merge_id, "source_case_id": source["id"], "source_case_no": source["case_no"],
            "moved_specimen_ids": moved_specimens, "moved_release_item_ids": moved_release_items,
        })
        result = {
            "executed_at": timestamp,
            "field_changes": field_changes,
            "moved_specimen_ids": moved_specimens,
            "moved_release_item_ids": moved_release_items,
            "alias_registered": alias_registered,
            "source_status": {"from": source_status_from, "to": "retired"},
            "references_after": {
                "target_specimen_ids": [
                    int(row["id"]) for row in self.connection.execute(
                        "SELECT id FROM specimens WHERE case_id=? ORDER BY id", (target["id"],)
                    ).fetchall()
                ],
                "source_remaining_specimens": int(self.connection.execute(
                    "SELECT COUNT(*) FROM specimens WHERE case_id=?", (source["id"],)
                ).fetchone()[0]),
            },
        }
        self.connection.execute(
            "UPDATE case_merges SET status='executed',result_json=?,executed_by=?,executed_at=? WHERE id=?",
            (json.dumps(result, ensure_ascii=False, sort_keys=True), actor, timestamp, merge_id),
        )
        self._outbox(
            f"forensic_case-merged-{merge_id}", "forensic_case.merged", "forensic_case", int(target["id"]),
            {
                "merge_id": merge_id, "source_case_id": source["id"], "target_case_id": target["id"],
                "moved_specimen_count": len(moved_specimens),
            },
            timestamp,
        )
        return self.repository.merge_detail(merge_id)

    def cancel(self, merge_id: int, actor: str) -> dict[str, Any]:
        merge = self.repository.require_merge(merge_id)
        if merge["status"] != "preview":
            raise ConflictError("归并单已处理，不能撤销", context={"status": merge["status"]})
        self.connection.execute(
            "UPDATE case_merges SET status='cancelled',executed_by=?,executed_at=? WHERE id=?",
            (actor, to_storage(self.clock.now()), merge_id),
        )
        return self.repository.merge_detail(merge_id)

    def resolve_number(self, query: str) -> dict[str, Any]:
        """按案件编号或登记别名解析案件；误建归并后旧编号继续解析到存续案件。"""
        normalized = normalize_identifier(query)
        case = self.repository.forensic_case_by_number(query.strip().upper())
        via = "case_no"
        if case is None and normalized:
            matches = [
                row for row in self.connection.execute("SELECT id,case_no FROM forensic_cases").fetchall()
                if normalize_identifier(str(row["case_no"])) == normalized
            ]
            if len(matches) == 1:
                case = self.repository.require_forensic_case(int(matches[0]["id"]))
                via = "case_no_normalized"
        if case is None and normalized:
            alias = self.repository.alias_by_normalized(normalized)
            if alias:
                case = self.repository.require_forensic_case(int(alias["case_id"]))
                via = "alias"
        if case is None:
            return {"query": query, "found": False, "via": None, "case": None, "merged": False,
                    "canonical_case": None, "merge_chain": []}
        chain: list[dict[str, Any]] = []
        current = case
        for _ in range(10):
            merge = self.repository.executed_merge_for_source(int(current["id"]))
            if merge is None:
                break
            chain.append({
                "merge_id": merge["id"],
                "source_case_id": merge["source_case_id"],
                "target_case_id": merge["target_case_id"],
            })
            current = self.repository.require_forensic_case(int(merge["target_case_id"]))
        return {
            "query": query,
            "found": True,
            "via": via,
            "case": self._summary(case),
            "merged": bool(chain),
            "canonical_case": self._summary(current),
            "merge_chain": chain,
        }

    def _validate_resolutions(self, resolutions: dict[str, Any]) -> dict[str, str]:
        validated: dict[str, str] = {}
        for field, keep in resolutions.items():
            if field not in MERGEABLE_FIELDS:
                raise ValidationError(
                    "归并字段不在可保留范围内", context={"field": field, "allowed": list(MERGEABLE_FIELDS)}
                )
            if keep not in {"source", "target"}:
                raise ValidationError("字段保留值只能为 source 或 target", context={"field": field})
            validated[field] = str(keep)
        return validated

    def _blocking_issues(self, source: dict[str, Any], target: dict[str, Any]) -> list[str]:
        issues: list[str] = []
        if int(source["id"]) == int(target["id"]):
            issues.append("归并来源与目标不能是同一案件")
        if self.repository.executed_merge_for_source(int(source["id"])):
            issues.append("来源案件已经被归并，不能重复迁移")
        if self.repository.executed_merge_for_source(int(target["id"])):
            issues.append("目标案件本身已被归并到其他案件，请选择存续案件")
        collision = self.connection.execute(
            "SELECT r1.id FROM release_items r1 JOIN release_items r2 ON r1.request_id=r2.request_id "
            "WHERE r1.case_id=? AND r2.case_id=? LIMIT 1",
            (source["id"], target["id"]),
        ).fetchone()
        if collision:
            issues.append("来源与目标在同一领用申请中均存在明细，无法直接迁移")
        normalized = normalize_identifier(str(source["case_no"]))
        holder = self.repository.alias_by_normalized(normalized)
        if holder and int(holder["case_id"]) not in {int(source["id"]), int(target["id"])}:
            issues.append("来源案件编号已被其他案件登记为别名，需先处理别名冲突")
        return issues

    def _warnings(self, source: dict[str, Any], target: dict[str, Any]) -> list[str]:
        warnings: list[str] = []
        reports = self.repository.case_reports(int(source["id"]))
        if reports:
            warnings.append("来源案件存在已签发报告，报告保持不可变并继续挂在原案件编号下")
        if source["status"] == "retired":
            warnings.append("来源案件已退出保存")
        if source["discipline"] != target["discipline"]:
            warnings.append("来源与目标鉴定专业不一致，请确认归并确属同一鉴定事项")
        held = self.connection.execute(
            "SELECT COUNT(*) FROM specimen_holds h JOIN specimens s ON s.id=h.specimen_id "
            "WHERE s.case_id=? AND h.released_at IS NULL",
            (source["id"],),
        ).fetchone()[0]
        if int(held):
            warnings.append("来源案件检材存在未解除的冻结，迁移后冻结继续有效")
        return warnings

    def _references(self, source_id: int) -> dict[str, Any]:
        specimens = records(self.connection.execute(
            "SELECT id,specimen_no,status FROM specimens WHERE case_id=? ORDER BY id", (source_id,)
        ).fetchall())
        specimen_ids = [int(item["id"]) for item in specimens]
        counts: dict[str, int] = {}
        if specimen_ids:
            placeholders = ",".join("?" for _ in specimen_ids)
            for table, label in (
                ("examinations", "examinations"),
                ("custody_events", "custody_events"),
                ("review_schedules", "review_schedules"),
                ("specimen_holds", "specimen_holds"),
                ("specimen_placements", "placements"),
                ("quality_alerts", "quality_alerts"),
            ):
                counts[label] = int(self.connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE specimen_id IN ({placeholders})", specimen_ids
                ).fetchone()[0])
        else:
            counts = {label: 0 for label in (
                "examinations", "custody_events", "review_schedules", "specimen_holds", "placements", "quality_alerts"
            )}
        release_items = records(self.connection.execute(
            "SELECT id,request_id,status FROM release_items WHERE case_id=? ORDER BY id", (source_id,)
        ).fetchall())
        reports = records(self.connection.execute(
            "SELECT id,report_no,report_kind,issued_at FROM case_reports WHERE case_id=? ORDER BY id", (source_id,)
        ).fetchall())
        aliases = records(self.connection.execute(
            "SELECT id,alias,alias_kind FROM case_number_aliases WHERE case_id=? ORDER BY id", (source_id,)
        ).fetchall())
        return {
            "specimens": specimens,
            "specimen_followers": counts,
            "release_items": release_items,
            "case_reports_stay": reports,
            "case_events_stay_count": int(self.connection.execute(
                "SELECT COUNT(*) FROM case_events WHERE case_id=?", (source_id,)
            ).fetchone()[0]),
            "aliases_stay": aliases,
        }

    def _apply_fields(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        resolutions: dict[str, str],
        timestamp: str,
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        columns: list[str] = []
        params: list[Any] = []
        for field in MERGEABLE_FIELDS:
            keep = resolutions.get(field, "target")
            chosen = source.get(field) if keep == "source" else target.get(field)
            changes.append({
                "field": field, "keep": keep, "before": target.get(field), "after": chosen,
            })
            if keep == "source" and source.get(field) != target.get(field):
                if field == "agency_id" and source.get(field) is not None:
                    self.repository.require_agency(int(source["agency_id"]))
                columns.append(f"{FIELD_COLUMNS[field]}=?")
                params.append(
                    json.dumps(chosen, ensure_ascii=False, sort_keys=True) if field == "passport" else chosen
                )
        if columns:
            params.extend([timestamp, target["id"]])
            self.connection.execute(
                f"UPDATE forensic_cases SET {','.join(columns)},version=version+1,updated_at=? WHERE id=?",
                params,
            )
        return changes

    def _register_source_number(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        merge_id: int,
        actor: str,
        timestamp: str,
    ) -> str:
        normalized = normalize_identifier(str(source["case_no"]))
        if not normalized:
            return ""
        existing = self.repository.alias_by_normalized(normalized)
        if existing and int(existing["case_id"]) == int(source["id"]):
            self.connection.execute(
                "UPDATE case_number_aliases SET case_id=? WHERE id=?", (target["id"], existing["id"])
            )
            return str(source["case_no"])
        if existing and int(existing["case_id"]) == int(target["id"]):
            return str(source["case_no"])
        self.connection.execute(
            "INSERT INTO case_number_aliases(case_id,alias,normalized_alias,alias_kind,source,created_by,created_at) "
            "VALUES(?,?,?,'merged_case_no',?,?,?)",
            (target["id"], source["case_no"], normalized, f"归并单 #{merge_id}", actor, timestamp),
        )
        return str(source["case_no"])

    def _summary(self, case: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": case["id"], "case_no": case["case_no"], "case_name": case["case_name"],
            "status": case["status"], "discipline": case["discipline"],
        }

    def _case_event(
        self,
        case_id: int,
        event_type: str,
        actor: str,
        from_status: str | None,
        to_status: str | None,
        detail: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO case_events(case_id,event_type,actor,from_status,to_status,detail_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                case_id, event_type, actor, from_status, to_status,
                json.dumps(detail, ensure_ascii=False, sort_keys=True), to_storage(self.clock.now()),
            ),
        )

    def _outbox(
        self,
        event_key: str,
        event_type: str,
        aggregate_type: str,
        aggregate_id: int,
        payload: dict[str, Any],
        timestamp: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO outbox_events(event_key,event_type,aggregate_type,aggregate_id,payload_json,available_at,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (event_key, event_type, aggregate_type, str(aggregate_id), json.dumps(payload, ensure_ascii=False), timestamp, timestamp),
        )
