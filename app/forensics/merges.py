from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.forensics.cases import ForensicCaseService
from app.forensics.repository import ForensicRepository, records
from app.services.audit import AuditContext, AuditService

MERGEABLE_FIELDS = ("case_name", "discipline", "entrusted_matter", "agency_id", "passport")

IMMUTABILITY_NOTE = "既有流转事件、检验记录、审计记录与已签发报告保持原样，仅变更归属引用"


class CaseMergeService:
    """误建案件的归并：预演引用迁移、逐字段决定保留值、执行并保留旧编号解析。"""

    def __init__(
        self,
        connection: sqlite3.Connection,
        clock: Clock | None = None,
        audit_context: AuditContext | None = None,
    ) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)
        self.forensic_cases = ForensicCaseService(connection, self.clock)
        self.audit = AuditService(connection, self.clock)
        self.audit_context = audit_context

    def preview(self, data: dict[str, Any]) -> dict[str, Any]:
        source = self.repository.require_forensic_case(int(data["source_case_id"]))
        target = self.repository.require_forensic_case(int(data["target_case_id"]))
        self._validate_pair(source, target)
        existing = self.repository.active_merge_for_source(int(source["id"]))
        if existing:
            raise ConflictError("该案件已有进行中的归并，请先执行或取消", context={"merge_id": existing["id"]})
        timestamp = to_storage(self.clock.now())
        plan = self._build_plan(source, target, timestamp)
        sequence = int(self.connection.execute(
            "SELECT COUNT(*) FROM case_merges WHERE source_case_id=? AND target_case_id=?",
            (source["id"], target["id"]),
        ).fetchone()[0]) + 1
        merge_no = f"MRG-{source['id']}-{target['id']}-{sequence:04d}"
        try:
            cursor = self.connection.execute(
                "INSERT INTO case_merges(merge_no,source_case_id,target_case_id,status,reason,plan_json,created_by,"
                "created_at,updated_at) VALUES(?,?,?,'previewed',?,?,?,?,?)",
                (
                    merge_no, source["id"], target["id"], data["reason"],
                    json.dumps(plan, ensure_ascii=False, sort_keys=True), data["actor"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("该案件已有进行中的归并，请先执行或取消") from exc
        merge_id = int(cursor.lastrowid)
        self._audit(data["actor"], "case_merge.previewed", merge_id, metadata={
            "merge_no": merge_no,
            "source_case_no": source["case_no"],
            "target_case_no": target["case_no"],
            "blocking_issues": len(plan["blocking_issues"]),
        })
        return self.repository.merge_detail(merge_id)

    def execute(self, merge_id: int, data: dict[str, Any]) -> dict[str, Any]:
        merge = self.repository.require_merge(merge_id)
        if int(merge["version"]) != int(data["expected_version"]):
            raise ConflictError("案件归并版本冲突", context={"current_version": merge["version"]})
        if merge["status"] != "previewed":
            raise ConflictError("归并已执行或已取消，不能重复执行")
        source = self.repository.require_forensic_case(int(merge["source_case_id"]))
        target = self.repository.require_forensic_case(int(merge["target_case_id"]))
        self._validate_pair(source, target)
        decisions = dict(data.get("field_decisions") or {})
        unknown = sorted(set(decisions) - set(MERGEABLE_FIELDS))
        if unknown:
            raise ValidationError("存在不允许调整的字段", context={"fields": unknown})
        invalid = sorted(key for key, value in decisions.items() if value not in {"source", "target"})
        if invalid:
            raise ValidationError("字段保留值只能选择 source 或 target", context={"fields": invalid})
        timestamp = to_storage(self.clock.now())
        plan = self._build_plan(source, target, timestamp)
        if plan["blocking_issues"]:
            raise ConflictError("存在阻断问题，无法执行归并", context={"blocking_issues": plan["blocking_issues"]})
        fields_updated = self._apply_field_decisions(source, target, decisions, timestamp)
        moved_specimens = self._move_specimens(source, target, timestamp)
        moved_release_items = self._move_release_items(source, target)
        moved_seals = self._move_seals(source, target)
        moved_aliases = self._move_aliases(source, target, data["actor"], timestamp)
        self._close_source(source, target, merge["reason"], data["actor"], timestamp)
        result = {
            "executed_at": timestamp,
            "field_decisions": decisions,
            "fields_updated": fields_updated,
            "moved_specimens": moved_specimens,
            "moved_release_items": moved_release_items,
            "moved_seal_registrations": moved_seals,
            "moved_aliases": moved_aliases,
            "followed_references": plan["followed_references"],
            "immutable_preserved": ["custody_events", "examinations", "audit_events", "report_signed_at"],
            "source_case": {"id": source["id"], "case_no": source["case_no"], "status": "retired"},
            "target_case": {"id": target["id"], "case_no": target["case_no"]},
        }
        self.connection.execute(
            "UPDATE case_merges SET status='executed',decisions_json=?,result_json=?,executed_by=?,executed_at=?,"
            "version=version+1,updated_at=? WHERE id=?",
            (
                json.dumps(decisions, ensure_ascii=False, sort_keys=True),
                json.dumps(result, ensure_ascii=False, sort_keys=True),
                data["actor"], timestamp, timestamp, merge_id,
            ),
        )
        self.forensic_cases.emit_outbox(
            f"forensic_case-merged-{merge_id}", "forensic_case.merged", "forensic_case", int(target["id"]),
            {
                "merge_id": merge_id,
                "source_case_no": source["case_no"],
                "target_case_no": target["case_no"],
                "moved_specimens": len(moved_specimens),
            },
            timestamp,
        )
        self._audit(data["actor"], "case_merge.executed", merge_id, before={
            "source_status": source["status"], "target_case_no": target["case_no"],
        }, after={
            "source_status": "retired", "merged_into_case_id": target["id"], "fields_updated": fields_updated,
        }, metadata={"merge_no": merge["merge_no"], "reason": merge["reason"]})
        return self.repository.merge_detail(merge_id)

    def cancel(self, merge_id: int, data: dict[str, Any]) -> dict[str, Any]:
        merge = self.repository.require_merge(merge_id)
        if int(merge["version"]) != int(data["expected_version"]):
            raise ConflictError("案件归并版本冲突", context={"current_version": merge["version"]})
        if merge["status"] != "previewed":
            raise ConflictError("只有预演中的归并可以取消")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE case_merges SET status='cancelled',cancelled_by=?,cancelled_at=?,cancel_reason=?,"
            "version=version+1,updated_at=? WHERE id=?",
            (data["actor"], timestamp, data["reason"], timestamp, merge_id),
        )
        self._audit(data["actor"], "case_merge.cancelled", merge_id, metadata={
            "merge_no": merge["merge_no"], "reason": data["reason"],
        })
        return self.repository.merge_detail(merge_id)

    def _validate_pair(self, source: dict[str, Any], target: dict[str, Any]) -> None:
        if int(source["id"]) == int(target["id"]):
            raise ValidationError("不能将案件归并到自身")
        if source.get("merged_into_case_id"):
            raise ConflictError("来源案件已经归并，无需再次归并")
        if target.get("merged_into_case_id"):
            raise ConflictError("目标案件已归并至其他案件，不能作为归并目标")
        if target["status"] == "retired":
            raise ConflictError("目标案件已退出保存，不能作为归并目标")

    def _build_plan(self, source: dict[str, Any], target: dict[str, Any], timestamp: str) -> dict[str, Any]:
        specimens = records(self.connection.execute(
            "SELECT id,specimen_no,status,available_quantity FROM specimens WHERE case_id=? ORDER BY id",
            (source["id"],),
        ).fetchall())
        specimen_ids = [int(item["id"]) for item in specimens]
        examinations: list[dict[str, Any]] = []
        followed = {"custody_events": 0, "review_schedules": 0, "quality_alerts": 0}
        if specimen_ids:
            placeholders = ",".join("?" for _ in specimen_ids)
            examinations = records(self.connection.execute(
                f"SELECT id,examination_no,status,specimen_id FROM examinations WHERE specimen_id IN ({placeholders}) ORDER BY id",
                tuple(specimen_ids),
            ).fetchall())
            for table, key in (
                ("custody_events", "custody_events"),
                ("review_schedules", "review_schedules"),
                ("quality_alerts", "quality_alerts"),
            ):
                followed[key] = int(self.connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE specimen_id IN ({placeholders})", tuple(specimen_ids)
                ).fetchone()[0])
        release_items = records(self.connection.execute(
            "SELECT i.id,i.request_id,i.quantity,i.status,r.request_no FROM release_items i "
            "JOIN release_requests r ON r.id=i.request_id WHERE i.case_id=? ORDER BY i.id",
            (source["id"],),
        ).fetchall())
        collisions = records(self.connection.execute(
            "SELECT i.request_id,r.request_no FROM release_items i JOIN release_requests r ON r.id=i.request_id "
            "WHERE i.case_id=? AND i.request_id IN (SELECT request_id FROM release_items WHERE case_id=?)",
            (target["id"], source["id"]),
        ).fetchall())
        blocking_issues = [
            {
                "type": "release_item_collision",
                "request_id": row["request_id"],
                "detail": f"领用申请 {row['request_no']} 同时包含两个案件的明细，请先调整申请",
            }
            for row in collisions
        ]
        field_options: dict[str, Any] = {}
        for field in MERGEABLE_FIELDS:
            source_value = source.get(field)
            target_value = target.get(field)
            field_options[field] = {
                "source": source_value,
                "target": target_value,
                "differ": source_value != target_value,
            }
        return {
            "generated_at": timestamp,
            "source_case": self._case_snapshot(source),
            "target_case": self._case_snapshot(target),
            "field_options": field_options,
            "references": {
                "specimens": specimens,
                "examinations": examinations,
                "release_items": release_items,
                "seal_registrations": int(self.connection.execute(
                    "SELECT COUNT(*) FROM seal_registry WHERE case_id=?", (source["id"],)
                ).fetchone()[0]),
                "case_aliases": int(self.connection.execute(
                    "SELECT COUNT(*) FROM case_aliases WHERE case_id=?", (source["id"],)
                ).fetchone()[0]),
                "supplement_packages": int(self.connection.execute(
                    "SELECT COUNT(*) FROM supplement_packages WHERE matched_case_id=?", (source["id"],)
                ).fetchone()[0]),
            },
            "followed_references": followed,
            "blocking_issues": blocking_issues,
            "immutability_note": IMMUTABILITY_NOTE,
        }

    def _case_snapshot(self, forensic_case: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": forensic_case["id"],
            "case_no": forensic_case["case_no"],
            "case_name": forensic_case["case_name"],
            "discipline": forensic_case["discipline"],
            "entrusted_matter": forensic_case["entrusted_matter"],
            "agency_id": forensic_case.get("agency_id"),
            "status": forensic_case["status"],
            "report_signed_at": forensic_case.get("report_signed_at"),
            "passport": forensic_case.get("passport", {}),
        }

    def _apply_field_decisions(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        decisions: dict[str, str],
        timestamp: str,
    ) -> dict[str, Any]:
        fields_updated: dict[str, Any] = {}
        columns: list[str] = []
        params: list[Any] = []
        for field, choice in sorted(decisions.items()):
            if choice != "source":
                continue
            new_value = source.get(field)
            if new_value == target.get(field):
                continue
            fields_updated[field] = {"before": target.get(field), "after": new_value}
            if field == "passport":
                columns.append("case_profile_json=?")
                params.append(json.dumps(new_value or {}, ensure_ascii=False, sort_keys=True))
            else:
                columns.append(f"{field}=?")
                params.append(new_value)
        if columns:
            params.extend([timestamp, target["id"]])
            self.connection.execute(
                f"UPDATE forensic_cases SET {','.join(columns)},version=version+1,updated_at=? WHERE id=?",
                params,
            )
        return fields_updated

    def _move_specimens(self, source: dict[str, Any], target: dict[str, Any], timestamp: str) -> list[dict[str, Any]]:
        moved = records(self.connection.execute(
            "SELECT id,specimen_no FROM specimens WHERE case_id=? ORDER BY id", (source["id"],)
        ).fetchall())
        self.connection.execute(
            "UPDATE specimens SET case_id=?,version=version+1,updated_at=? WHERE case_id=?",
            (target["id"], timestamp, source["id"]),
        )
        return moved

    def _move_release_items(self, source: dict[str, Any], target: dict[str, Any]) -> list[int]:
        moved = [
            int(row["id"]) for row in self.connection.execute(
                "SELECT id FROM release_items WHERE case_id=? ORDER BY id", (source["id"],)
            ).fetchall()
        ]
        self.connection.execute(
            "UPDATE release_items SET case_id=? WHERE case_id=?", (target["id"], source["id"])
        )
        return moved

    def _move_seals(self, source: dict[str, Any], target: dict[str, Any]) -> int:
        cursor = self.connection.execute(
            "UPDATE OR IGNORE seal_registry SET case_id=? WHERE case_id=?", (target["id"], source["id"])
        )
        return int(cursor.rowcount)

    def _move_aliases(self, source: dict[str, Any], target: dict[str, Any], actor: str, timestamp: str) -> int:
        cursor = self.connection.execute(
            "UPDATE case_aliases SET case_id=? WHERE case_id=?", (target["id"], source["id"])
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO case_aliases(alias_no,case_id,kind,created_by,created_at) VALUES(?,?,'merged_from',?,?)",
            (str(source["case_no"]).upper(), target["id"], actor, timestamp),
        )
        return int(cursor.rowcount)

    def _close_source(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        reason: str,
        actor: str,
        timestamp: str,
    ) -> None:
        previous_status = source["status"]
        self.connection.execute(
            "UPDATE forensic_cases SET status='retired',merged_into_case_id=?,return_reason=?,"
            "version=version+1,updated_at=? WHERE id=?",
            (target["id"], f"归并至 {target['case_no']}：{reason}", timestamp, source["id"]),
        )
        self.forensic_cases.record_event(
            int(source["id"]), "merged_away", actor, previous_status, "retired",
            {"merge_target_case_id": target["id"], "merge_target_case_no": target["case_no"], "reason": reason},
        )
        self.forensic_cases.record_event(
            int(target["id"]), "merge_received", actor, None, None,
            {"source_case_id": source["id"], "source_case_no": source["case_no"], "reason": reason},
        )

    def _audit(
        self,
        actor: str,
        action: str,
        merge_id: int,
        *,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        context = self.audit_context or AuditContext(None, actor)
        self.audit.record(
            context,
            action=action,
            resource_type="case_merge",
            reagency_id=merge_id,
            before=before,
            after=after,
            metadata=metadata or {},
        )
