from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.forensics.cases import ForensicCaseService
from app.forensics.custody import CustodyService
from app.forensics.repository import ForensicRepository, case_closed, record
from app.services.audit import AuditContext, AuditService
from app.services.idempotency import IdempotencyService

DOCUMENT_WEIGHT = 50
ALIAS_WEIGHT = 40
PROFILE_ALIAS_WEIGHT = 35
SEAL_WEIGHT = 30
AGENCY_WEIGHT = 10
CANDIDATE_THRESHOLD = 40

REGISTER_SCOPE = "supplements.register"


def normalize_reference(value: str) -> str:
    """委托编号写法归一化：忽略大小写、空格与分隔符号，便于比对不同写法的同一编号。"""
    return "".join(character for character in str(value).upper() if character.isalnum())


class SupplementService:
    """补送包识别、人工确认、冲突处理与检材接收。"""

    def __init__(
        self,
        connection: sqlite3.Connection,
        clock: Clock | None = None,
        audit_context: AuditContext | None = None,
    ) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)
        self.custody = CustodyService(connection, self.clock)
        self.forensic_cases = ForensicCaseService(connection, self.clock)
        self.idempotency = IdempotencyService(connection, self.clock)
        self.audit = AuditService(connection, self.clock)
        self.audit_context = audit_context

    def register_package(self, data: dict[str, Any]) -> dict[str, Any]:
        self.repository.require_agency(int(data["agency_id"]))
        payload = {
            "package_no": data["package_no"],
            "agency_id": int(data["agency_id"]),
            "document_no": data.get("document_no", ""),
            "case_no_alias": data.get("case_no_alias", ""),
            "seal_nos": list(data.get("seal_nos", [])),
            "notes": data.get("notes", ""),
        }
        replay = self.idempotency.lookup(REGISTER_SCOPE, data["idempotency_key"], payload)
        if replay is not None:
            return {**replay.body, "replayed": True}
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO supplement_packages(package_no,idempotency_key,agency_id,document_no,case_no_alias,"
                "seal_nos_json,notes,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'pending',?,?,?)",
                (
                    data["package_no"], data["idempotency_key"], int(data["agency_id"]),
                    data.get("document_no", ""), data.get("case_no_alias", ""),
                    json.dumps(list(data.get("seal_nos", [])), ensure_ascii=False),
                    data.get("notes", ""), data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("补送包编号或幂等键已经存在") from exc
        package_id = int(cursor.lastrowid)
        candidates = self._build_candidates(package_id, data, timestamp)
        status = "pending" if candidates else "quarantined"
        self.connection.execute(
            "UPDATE supplement_packages SET status=?,updated_at=? WHERE id=?", (status, timestamp, package_id)
        )
        self._audit(data["created_by"], "supplement.registered", package_id, metadata={
            "package_no": data["package_no"], "candidate_count": len(candidates), "status": status,
        })
        body = {"package": self.repository.package_detail(package_id), "replayed": False}
        saved = self.idempotency.save(REGISTER_SCOPE, data["idempotency_key"], payload, body, 201)
        if saved.replayed:
            return {**saved.body, "replayed": True}
        return body

    def confirm(self, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        package = self.repository.require_package(package_id)
        if int(package["version"]) != int(data["expected_version"]):
            raise ConflictError("补送包版本冲突", context={"current_version": package["version"]})
        if package["status"] == "confirmed":
            raise ConflictError("补送包已确认归并，不能重复确认")
        if package["status"] == "conflict":
            raise ConflictError("补送包正在冲突处理中，请先完成冲突处理")
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case.get("merged_into_case_id"):
            raise ConflictError(
                "目标案件已归并至其他案件，请选择归并后的案件",
                context={"merged_into_case_id": forensic_case["merged_into_case_id"]},
            )
        candidate_ids = {
            int(row["case_id"]) for row in self.connection.execute(
                "SELECT case_id FROM supplement_candidates WHERE package_id=?", (package_id,)
            ).fetchall()
        }
        if int(forensic_case["id"]) not in candidate_ids and not data.get("reason", "").strip():
            raise ValidationError("所选案件不在候选列表中，必须填写确认理由")
        timestamp = to_storage(self.clock.now())
        conflicts = self._detect_conflicts(package, forensic_case)
        if conflicts:
            conflict = {
                "types": sorted(conflicts),
                "attempted_case_id": forensic_case["id"],
                "attempted_case_no": forensic_case["case_no"],
                "attempted_by": data["actor"],
                "attempted_at": timestamp,
                "reason": data.get("reason", ""),
                **conflicts,
            }
            self.connection.execute(
                "UPDATE supplement_packages SET status='conflict',conflict_json=?,version=version+1,updated_at=? WHERE id=?",
                (json.dumps(conflict, ensure_ascii=False, sort_keys=True), timestamp, package_id),
            )
            self._audit(data["actor"], "supplement.conflict_raised", package_id, metadata={
                "package_no": package["package_no"], "types": sorted(conflicts), "case_no": forensic_case["case_no"],
            })
            return self.repository.package_detail(package_id)
        self._apply_confirmation(package, forensic_case, data["actor"], data.get("reason", ""), timestamp)
        return self.repository.package_detail(package_id)

    def resolve_conflict(self, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        package = self.repository.require_package(package_id)
        if int(package["version"]) != int(data["expected_version"]):
            raise ConflictError("补送包版本冲突", context={"current_version": package["version"]})
        if package["status"] != "conflict":
            raise ConflictError("补送包不在冲突处理中")
        conflict = package.get("conflict", {})
        case_id = conflict.get("attempted_case_id")
        if not case_id:
            raise ConflictError("冲突记录缺少目标案件，无法处理")
        forensic_case = self.repository.require_forensic_case(int(case_id))
        timestamp = to_storage(self.clock.now())
        if data["action"] == "reject":
            self.connection.execute(
                "UPDATE supplement_packages SET status='quarantined',resolved_by=?,resolved_at=?,resolution_reason=?,"
                "version=version+1,updated_at=? WHERE id=?",
                (data["actor"], timestamp, data["reason"], timestamp, package_id),
            )
            self._audit(data["actor"], "supplement.conflict_resolved", package_id, metadata={
                "package_no": package["package_no"], "action": "reject", "reason": data["reason"],
            })
            return self.repository.package_detail(package_id)
        if forensic_case["status"] == "retired":
            self.connection.execute(
                "UPDATE forensic_cases SET status='quarantine',return_reason='',version=version+1,updated_at=? WHERE id=?",
                (timestamp, forensic_case["id"]),
            )
            self.forensic_cases.record_event(
                int(forensic_case["id"]), "reopened", data["actor"], "retired", "quarantine",
                {"reason": data["reason"], "package_no": package["package_no"]},
            )
            forensic_case = self.repository.require_forensic_case(int(forensic_case["id"]))
        self._apply_confirmation(
            package, forensic_case, data["actor"], data["reason"], timestamp,
            resolved_by=data["actor"], resolution_reason=data["reason"],
        )
        self._audit(data["actor"], "supplement.conflict_resolved", package_id, metadata={
            "package_no": package["package_no"], "action": "override_confirm",
            "case_no": forensic_case["case_no"], "reason": data["reason"],
        })
        return self.repository.package_detail(package_id)

    def add_item(self, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        package = self.repository.require_package(package_id)
        if package["status"] != "confirmed":
            raise ConflictError("补送包尚未确认归并，不能接收检材")
        existing = record(self.connection.execute(
            "SELECT i.* FROM supplement_package_items i JOIN specimens s ON s.id=i.specimen_id "
            "WHERE i.package_id=? AND s.specimen_no=?",
            (package_id, data["specimen_no"]),
        ).fetchone())
        if existing:
            return {
                "item": existing,
                "specimen": self.repository.specimen_detail(int(existing["specimen_id"])),
                "replayed": True,
            }
        specimen = self.custody.create_specimen({
            "specimen_no": data["specimen_no"],
            "case_id": int(package["matched_case_id"]),
            "parent_specimen_id": data.get("parent_specimen_id"),
            "received_year": data["received_year"],
            "initial_quantity": data["initial_quantity"],
            "integrity_percent": data.get("integrity_percent"),
            "packaging": data.get("packaging", ""),
            "sealed_on": data.get("sealed_on"),
            "created_by": data["created_by"],
        })
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO supplement_package_items(package_id,specimen_id,created_by,created_at) VALUES(?,?,?,?)",
            (package_id, specimen["id"], data["created_by"], timestamp),
        )
        self._audit(data["created_by"], "supplement.item_received", package_id, metadata={
            "package_no": package["package_no"], "specimen_no": data["specimen_no"],
            "case_id": package["matched_case_id"],
        })
        return {
            "item": record(self.connection.execute(
                "SELECT * FROM supplement_package_items WHERE id=?", (cursor.lastrowid,)
            ).fetchone()),
            "specimen": specimen,
            "replayed": False,
        }

    def _build_candidates(self, package_id: int, data: dict[str, Any], timestamp: str) -> list[dict[str, Any]]:
        seal_rows = self.repository.seal_owners(list(data.get("seal_nos", [])))
        seals_by_case: dict[int, list[str]] = {}
        for row in seal_rows:
            seals_by_case.setdefault(int(row["case_id"]), []).append(row["seal_no"])
        document_norm = normalize_reference(data.get("document_no", ""))
        alias_norm = normalize_reference(data.get("case_no_alias", ""))
        candidates: list[dict[str, Any]] = []
        for forensic_case in self.repository.matching_cases():
            evidence = self._case_evidence(forensic_case, data, document_norm, alias_norm, seals_by_case)
            score = sum(item["weight"] for item in evidence)
            if score < CANDIDATE_THRESHOLD:
                continue
            self.connection.execute(
                "INSERT INTO supplement_candidates(package_id,case_id,score,evidence_json,created_at) VALUES(?,?,?,?,?)",
                (package_id, forensic_case["id"], score, json.dumps(evidence, ensure_ascii=False), timestamp),
            )
            candidates.append({"case_id": forensic_case["id"], "score": score, "evidence": evidence})
        candidates.sort(key=lambda item: item["score"], reverse=True)
        return candidates

    def _case_evidence(
        self,
        forensic_case: dict[str, Any],
        data: dict[str, Any],
        document_norm: str,
        alias_norm: str,
        seals_by_case: dict[int, list[str]],
    ) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        passport = forensic_case.get("passport", {})
        documents = {
            normalize_reference(passport[key])
            for key in ("commission_document", "document_no")
            if passport.get(key)
        }
        if document_norm and document_norm in documents:
            evidence.append({
                "type": "document_no",
                "detail": f"原始文书号与案件 {forensic_case['case_no']} 的委托文书一致",
                "weight": DOCUMENT_WEIGHT,
            })
        if alias_norm:
            if alias_norm == normalize_reference(forensic_case["case_no"]):
                evidence.append({
                    "type": "case_no_alias",
                    "detail": "案号别名与案件编号一致",
                    "weight": ALIAS_WEIGHT,
                })
            elif any(
                normalize_reference(alias["alias_no"]) == alias_norm
                for alias in self.repository.aliases_for_case(int(forensic_case["id"]))
            ):
                evidence.append({
                    "type": "case_no_alias",
                    "detail": "案号别名与案件已登记别名一致",
                    "weight": ALIAS_WEIGHT,
                })
            elif any(
                normalize_reference(item) == alias_norm
                for item in passport.get("aliases", []) or []
            ):
                evidence.append({
                    "type": "profile_alias",
                    "detail": "案号别名与案件档案中的别名一致",
                    "weight": PROFILE_ALIAS_WEIGHT,
                })
        matched_seals = seals_by_case.get(int(forensic_case["id"]), [])
        if matched_seals:
            evidence.append({
                "type": "seal_no",
                "detail": f"封识号 {'、'.join(sorted(matched_seals))} 已登记在本案件",
                "weight": SEAL_WEIGHT,
            })
        if data.get("agency_id") and int(data["agency_id"]) == int(forensic_case.get("agency_id") or 0):
            evidence.append({
                "type": "agency",
                "detail": "同一委托机构送检",
                "weight": AGENCY_WEIGHT,
            })
        return evidence

    def _detect_conflicts(self, package: dict[str, Any], forensic_case: dict[str, Any]) -> dict[str, Any]:
        conflicts: dict[str, Any] = {}
        owners = [
            {"seal_no": row["seal_no"], "case_id": row["case_id"], "case_no": row["case_no"]}
            for row in self.repository.seal_owners(list(package["seal_nos"]))
            if int(row["case_id"]) != int(forensic_case["id"])
        ]
        if owners:
            conflicts["seal_conflict"] = owners
        if case_closed(forensic_case):
            conflicts["case_closed"] = {
                "status": forensic_case["status"],
                "report_signed_at": forensic_case.get("report_signed_at"),
            }
        return conflicts

    def _apply_confirmation(
        self,
        package: dict[str, Any],
        forensic_case: dict[str, Any],
        actor: str,
        reason: str,
        timestamp: str,
        *,
        resolved_by: str | None = None,
        resolution_reason: str = "",
    ) -> None:
        for seal_no in package["seal_nos"]:
            self.connection.execute(
                "INSERT OR IGNORE INTO seal_registry(seal_no,case_id,package_id,registered_by,created_at) VALUES(?,?,?,?,?)",
                (seal_no, forensic_case["id"], package["id"], actor, timestamp),
            )
        alias = package.get("case_no_alias", "").strip()
        if alias and normalize_reference(alias) != normalize_reference(forensic_case["case_no"]):
            self.connection.execute(
                "INSERT OR IGNORE INTO case_aliases(alias_no,case_id,kind,created_by,created_at) VALUES(?,?,'supplement',?,?)",
                (alias.upper(), forensic_case["id"], actor, timestamp),
            )
        if resolved_by is None:
            self.connection.execute(
                "UPDATE supplement_packages SET status='confirmed',matched_case_id=?,decided_by=?,decided_at=?,"
                "decision_reason=?,version=version+1,updated_at=? WHERE id=?",
                (forensic_case["id"], actor, timestamp, reason, timestamp, package["id"]),
            )
        else:
            self.connection.execute(
                "UPDATE supplement_packages SET status='confirmed',matched_case_id=?,decided_by=?,decided_at=?,"
                "decision_reason=?,resolved_by=?,resolved_at=?,resolution_reason=?,version=version+1,updated_at=? WHERE id=?",
                (forensic_case["id"], actor, timestamp, reason, resolved_by, timestamp, resolution_reason,
                 timestamp, package["id"]),
            )
        self.forensic_cases.record_event(
            int(forensic_case["id"]), "supplement_confirmed", actor, None, None,
            {"package_id": package["id"], "package_no": package["package_no"], "reason": reason},
        )
        self._audit(actor, "supplement.confirmed", package["id"], metadata={
            "package_no": package["package_no"], "case_no": forensic_case["case_no"], "reason": reason,
        })

    def _audit(self, actor: str, action: str, package_id: int, *, metadata: dict[str, Any]) -> None:
        context = self.audit_context or AuditContext(None, actor)
        self.audit.record(
            context,
            action=action,
            resource_type="supplement_package",
            reagency_id=package_id,
            metadata=metadata,
        )
