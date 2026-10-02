from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.forensics.custody import CustodyService
from app.forensics.identifiers import normalize_identifier
from app.forensics.repository import ForensicRepository, records
from app.services.idempotency import IdempotencyService

# 证据权重：委托机构仅作弱线索，文书号/案号别名/封识号才是可确认候选的强证据。
EVIDENCE_WEIGHTS = {"agency": 1, "commission_document": 3, "alias": 3, "seal": 4}
CANDIDATE_THRESHOLD = 3
IDEMPOTENCY_SCOPE = "supplementary_packages.submit"


class SupplementaryService:
    """补送识别与归并：登记补送包、形成带证据候选、人工确认接收、冲突处理。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)
        self.custody = CustodyService(connection, self.clock)
        self.idempotency = IdempotencyService(connection, self.clock)

    def submit_package(self, data: dict[str, Any]) -> dict[str, Any]:
        stored = self.idempotency.lookup(IDEMPOTENCY_SCOPE, data["idempotency_key"], data)
        if stored is not None:
            return stored.body
        if data.get("agency_id"):
            self.repository.require_agency(int(data["agency_id"]))
        aliases = [alias for alias in data.get("case_number_aliases", []) if str(alias).strip()]
        reference_seals = [seal for seal in data.get("reference_seals", []) if str(seal).strip()]
        candidates = self._compute_candidates(
            agency_id=data.get("agency_id"),
            commission_document=data.get("commission_document", ""),
            aliases=aliases,
            seal_numbers=reference_seals,
        )
        status = "pending" if len(candidates) == 1 else "quarantined"
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO supplementary_packages(package_no,agency_id,commission_document,aliases_json,"
                "reference_seals_json,candidates_json,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    data["package_no"], data.get("agency_id"), data.get("commission_document", ""),
                    json.dumps(aliases, ensure_ascii=False), json.dumps(reference_seals, ensure_ascii=False),
                    json.dumps(candidates, ensure_ascii=False),
                    status, data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("补送包编号已经存在") from exc
        package_id = int(cursor.lastrowid)
        for item in data["items"]:
            self.connection.execute(
                "INSERT INTO supplementary_package_items(package_id,specimen_no,seal_no,quantity,received_year,packaging) "
                "VALUES(?,?,?,?,?,?)",
                (
                    package_id, item["specimen_no"], item.get("seal_no") or "", item["quantity"],
                    item["received_year"], item.get("packaging", ""),
                ),
            )
        self._event(package_id, "submitted", data["created_by"], {
            "item_count": len(data["items"]), "candidate_count": len(candidates), "status": status,
        })
        if status == "quarantined":
            reason = "无任何候选案件" if not candidates else "存在多个候选案件"
            self._event(package_id, "quarantined", data["created_by"], {
                "reason": f"{reason}，材料保持隔离，禁止自动归并",
            })
        body = self.repository.package_detail(package_id)
        self.idempotency.save(IDEMPOTENCY_SCOPE, data["idempotency_key"], data, body, 201)
        return body

    def confirm(self, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        package = self.repository.require_package(package_id)
        if package["status"] not in {"pending", "quarantined"}:
            raise ConflictError("补送包当前状态不能确认", context={"status": package["status"]})
        if int(package["version"]) != int(data["expected_version"]):
            raise ConflictError("补送包版本冲突", context={"current_version": package["version"]})
        target = self.repository.require_forensic_case(int(data["case_id"]))
        canonical = self.repository.executed_merge_for_source(int(target["id"]))
        if canonical:
            raise ConflictError(
                "目标案件已归并至其他案件，请确认到归并后的案件",
                context={"canonical_case_id": canonical["target_case_id"], "merge_id": canonical["id"]},
            )
        candidate_ids = {int(candidate["case_id"]) for candidate in package.get("candidates", [])}
        reason = data.get("reason", "").strip()
        if package["status"] == "quarantined" and not reason:
            raise ValidationError("隔离补送包人工指定案件时必须填写理由")
        if int(target["id"]) not in candidate_ids and not reason:
            raise ValidationError("确认非候选案件时必须填写理由")
        items = records(self.connection.execute(
            "SELECT * FROM supplementary_package_items WHERE package_id=? ORDER BY id", (package_id,)
        ).fetchall())
        conflicts = self._conflicts(package, items, target)
        timestamp = to_storage(self.clock.now())
        if conflicts:
            self.connection.execute(
                "UPDATE supplementary_packages SET status='conflict',conflicts_json=?,confirmed_case_id=?,"
                "decided_by=?,decided_at=?,decision_reason=?,version=version+1,updated_at=? WHERE id=?",
                (
                    json.dumps(conflicts, ensure_ascii=False), target["id"], data["actor"], timestamp,
                    reason, timestamp, package_id,
                ),
            )
            self._event(package_id, "conflict_raised", data["actor"], {
                "case_id": target["id"], "case_no": target["case_no"], "conflicts": conflicts, "reason": reason,
            })
            return self.repository.package_detail(package_id)
        self._receive(package, items, target, data["actor"], reason, via="confirm")
        return self.repository.package_detail(package_id)

    def resolve_conflict(self, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        package = self.repository.require_package(package_id)
        if package["status"] != "conflict":
            raise ConflictError("只有冲突状态的补送包可以执行冲突处理", context={"status": package["status"]})
        if int(package["version"]) != int(data["expected_version"]):
            raise ConflictError("补送包版本冲突", context={"current_version": package["version"]})
        timestamp = to_storage(self.clock.now())
        if data["decision"] == "reject":
            self.connection.execute(
                "UPDATE supplementary_packages SET status='rejected',decided_by=?,decided_at=?,decision_reason=?,"
                "version=version+1,updated_at=? WHERE id=?",
                (data["actor"], timestamp, data["reason"], timestamp, package_id),
            )
            self._event(package_id, "conflict_resolved", data["actor"], {
                "decision": "reject", "reason": data["reason"], "conflicts": package.get("conflicts", []),
            })
            return self.repository.package_detail(package_id)
        target = self.repository.require_forensic_case(int(package["confirmed_case_id"]))
        canonical = self.repository.executed_merge_for_source(int(target["id"]))
        if canonical:
            raise ConflictError(
                "目标案件已归并至其他案件，请重新确认归并后的案件",
                context={"canonical_case_id": canonical["target_case_id"], "merge_id": canonical["id"]},
            )
        items = records(self.connection.execute(
            "SELECT * FROM supplementary_package_items WHERE package_id=? ORDER BY id", (package_id,)
        ).fetchall())
        overridden = self._conflicts(package, items, target)
        self._receive(package, items, target, data["actor"], data["reason"], via="conflict_resolution")
        self._event(package_id, "conflict_resolved", data["actor"], {
            "decision": "receive", "reason": data["reason"], "overridden_conflicts": overridden,
        })
        return self.repository.package_detail(package_id)

    def _conflicts(self, package: dict[str, Any], items: list[dict[str, Any]], target: dict[str, Any]) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []
        if target["status"] == "retired":
            conflicts.append({
                "kind": "case_closed", "case_id": target["id"], "case_no": target["case_no"],
                "detail": "原案件已关闭退出保存，接收补送材料需要冲突处理",
            })
        elif target["status"] not in {"accepted", "restricted", "quarantine"}:
            conflicts.append({
                "kind": "case_not_receivable", "case_id": target["id"], "case_no": target["case_no"],
                "detail": f"原案件状态为 {target['status']}，不能接收补送检材",
            })
        reports = self.repository.case_reports(int(target["id"]))
        if reports:
            conflicts.append({
                "kind": "case_issued", "case_id": target["id"], "case_no": target["case_no"],
                "report_nos": [report["report_no"] for report in reports],
                "detail": "原案件已签发报告，补送材料需要冲突处理",
            })
        seal_index = self._seal_index()
        for item in items:
            existing = self.connection.execute(
                "SELECT id,case_id FROM specimens WHERE specimen_no=?", (item["specimen_no"],)
            ).fetchone()
            if existing:
                conflicts.append({
                    "kind": "specimen_no_exists", "specimen_no": item["specimen_no"],
                    "holder_case_id": existing["case_id"],
                    "detail": "检材编号已被登记，疑似重复送检",
                })
            seal = item.get("seal_no") or ""
            if not seal:
                continue
            for holder in seal_index.get(normalize_identifier(seal), []):
                if int(holder["case_id"]) != int(target["id"]):
                    conflicts.append({
                        "kind": "seal_occupied", "seal_no": seal,
                        "holder_case_id": holder["case_id"], "holder_case_no": holder["case_no"],
                        "holder_specimen_no": holder["specimen_no"],
                        "detail": "封识号已被其他案件的检材占用",
                    })
                else:
                    conflicts.append({
                        "kind": "seal_duplicate", "seal_no": seal,
                        "holder_case_id": holder["case_id"], "holder_case_no": holder["case_no"],
                        "holder_specimen_no": holder["specimen_no"],
                        "detail": "封识号与目标案件既有检材重复，疑似重复送检",
                    })
        all_cases = self.connection.execute("SELECT id,case_no FROM forensic_cases").fetchall()
        for alias in package.get("aliases", []):
            normalized = normalize_identifier(alias)
            if not normalized:
                continue
            holder = self.repository.alias_by_normalized(normalized)
            if holder and int(holder["case_id"]) != int(target["id"]):
                conflicts.append({
                    "kind": "alias_occupied", "alias": alias,
                    "holder_case_id": holder["case_id"],
                    "detail": "案号别名已登记在其他案件下",
                })
                continue
            for case_row in all_cases:
                if int(case_row["id"]) != int(target["id"]) and normalize_identifier(case_row["case_no"]) == normalized:
                    conflicts.append({
                        "kind": "alias_occupied", "alias": alias,
                        "holder_case_id": case_row["id"],
                        "detail": "案号别名与其他案件编号相同",
                    })
        return conflicts

    def _receive(
        self,
        package: dict[str, Any],
        items: list[dict[str, Any]],
        target: dict[str, Any],
        actor: str,
        reason: str,
        *,
        via: str,
    ) -> None:
        timestamp = to_storage(self.clock.now())
        specimen_ids: list[int] = []
        for item in items:
            duplicate = self.connection.execute(
                "SELECT id FROM specimens WHERE specimen_no=?", (item["specimen_no"],)
            ).fetchone()
            if duplicate:
                raise ConflictError(
                    f"检材编号 {item['specimen_no']} 已经存在，不能重复接收",
                    context={"specimen_no": item["specimen_no"]},
                )
            created = self.custody.create_specimen({
                "specimen_no": item["specimen_no"], "case_id": target["id"], "parent_specimen_id": None,
                "received_year": item["received_year"], "initial_quantity": item["quantity"],
                "integrity_percent": None, "packaging": item.get("packaging", ""), "sealed_on": None,
                "seal_no": item.get("seal_no") or None, "created_by": actor,
            })
            specimen_ids.append(int(created["id"]))
            self.connection.execute(
                "UPDATE supplementary_package_items SET specimen_id=? WHERE id=?",
                (created["id"], item["id"]),
            )
        skipped_aliases: list[str] = []
        target_number = normalize_identifier(target["case_no"])
        for alias in package.get("aliases", []):
            normalized = normalize_identifier(alias)
            if not normalized or normalized == target_number:
                continue
            try:
                self.connection.execute(
                    "INSERT INTO case_number_aliases(case_id,alias,normalized_alias,alias_kind,source,created_by,created_at) "
                    "VALUES(?,?,?,'commission_no',?,?,?)",
                    (target["id"], alias, normalized, f"补送包 {package['package_no']}", actor, timestamp),
                )
            except sqlite3.IntegrityError:
                skipped_aliases.append(alias)
        self.connection.execute(
            "UPDATE supplementary_packages SET status='received',confirmed_case_id=?,decided_by=?,decided_at=?,"
            "decision_reason=?,version=version+1,updated_at=? WHERE id=?",
            (target["id"], actor, timestamp, reason, timestamp, package["id"]),
        )
        self._event(int(package["id"]), "received", actor, {
            "case_id": target["id"], "case_no": target["case_no"], "specimen_ids": specimen_ids,
            "via": via, "reason": reason, "skipped_aliases": skipped_aliases,
        })
        self.connection.execute(
            "INSERT INTO case_events(case_id,event_type,actor,from_status,to_status,detail_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                target["id"], "supplementary_received", actor, None, None,
                json.dumps({
                    "package_id": package["id"], "package_no": package["package_no"],
                    "specimen_ids": specimen_ids, "via": via,
                }, ensure_ascii=False, sort_keys=True),
                timestamp,
            ),
        )
        self._outbox(
            f"supplementary-received-{package['id']}", "supplementary_package.received",
            "supplementary_package", int(package["id"]),
            {"case_id": target["id"], "specimen_ids": specimen_ids, "via": via}, timestamp,
        )

    def _compute_candidates(
        self,
        *,
        agency_id: int | None,
        commission_document: str,
        aliases: list[str],
        seal_numbers: list[str],
    ) -> list[dict[str, Any]]:
        cases = records(self.connection.execute(
            "SELECT id,case_no,agency_id,status,case_profile_json FROM forensic_cases"
        ).fetchall())
        canonical: dict[int, int] = {}
        merged_numbers: dict[int, str] = {}
        for row in self.connection.execute(
            "SELECT source_case_id,target_case_id FROM case_merges WHERE status='executed'"
        ).fetchall():
            canonical[int(row["source_case_id"])] = int(row["target_case_id"])
        case_by_id = {int(case["id"]): case for case in cases}
        for source_id in canonical:
            merged_numbers[source_id] = str(case_by_id[source_id]["case_no"]) if source_id in case_by_id else ""

        def canonical_of(case_id: int) -> int:
            seen: set[int] = set()
            current = case_id
            while current in canonical and current not in seen:
                seen.add(current)
                current = canonical[current]
            return current

        scores: dict[int, dict[str, Any]] = {}

        def add_evidence(case_id: int, kind: str, detail: str, value: str) -> None:
            target_id = canonical_of(case_id)
            entry = scores.setdefault(target_id, {"case_id": target_id, "score": 0, "evidence": []})
            evidence: dict[str, Any] = {"kind": kind, "detail": detail, "value": value}
            if target_id != case_id:
                evidence["via_merged_case_no"] = merged_numbers.get(case_id, "")
            entry["evidence"].append(evidence)
            entry["score"] += EVIDENCE_WEIGHTS[kind]

        if agency_id:
            for case in cases:
                if case.get("agency_id") is not None and int(case["agency_id"]) == int(agency_id):
                    add_evidence(int(case["id"]), "agency", "委托机构一致", str(agency_id))
        document_key = normalize_identifier(commission_document)
        if document_key:
            for case in cases:
                passport = case.get("passport", {})
                stored = normalize_identifier(str(passport.get("commission_document", "")))
                if stored and stored == document_key:
                    add_evidence(int(case["id"]), "commission_document", "原始文书号一致", commission_document)
        alias_index: dict[str, list[dict[str, Any]]] = {}
        for row in self.connection.execute("SELECT case_id,alias,normalized_alias FROM case_number_aliases").fetchall():
            alias_index.setdefault(str(row["normalized_alias"]), []).append(
                {"case_id": int(row["case_id"]), "alias": row["alias"]}
            )
        for alias in aliases:
            normalized = normalize_identifier(alias)
            if not normalized:
                continue
            for case in cases:
                if normalize_identifier(str(case["case_no"])) == normalized:
                    add_evidence(int(case["id"]), "alias", "案号别名与案件编号一致", alias)
            for hit in alias_index.get(normalized, []):
                add_evidence(hit["case_id"], "alias", f"案号别名命中登记别名 {hit['alias']}", alias)
        seal_index = self._seal_index()
        for seal in seal_numbers:
            normalized = normalize_identifier(seal)
            if not normalized:
                continue
            for holder in seal_index.get(normalized, []):
                add_evidence(
                    holder["case_id"], "seal",
                    f"封识号命中检材 {holder['specimen_no']}", seal,
                )
        candidates = [entry for entry in scores.values() if entry["score"] >= CANDIDATE_THRESHOLD]
        for entry in candidates:
            case = case_by_id.get(int(entry["case_id"]))
            if case:
                entry["case_no"] = case["case_no"]
                entry["status"] = case["status"]
        candidates.sort(key=lambda entry: (-entry["score"], entry["case_id"]))
        return candidates

    def _seal_index(self) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        rows = self.connection.execute(
            "SELECT s.id,s.specimen_no,s.case_id,s.seal_no,c.case_no FROM specimens s "
            "JOIN forensic_cases c ON c.id=s.case_id WHERE s.seal_no<>''"
        ).fetchall()
        for row in rows:
            normalized = normalize_identifier(str(row["seal_no"]))
            if not normalized:
                continue
            index.setdefault(normalized, []).append({
                "specimen_id": int(row["id"]),
                "specimen_no": row["specimen_no"],
                "case_id": int(row["case_id"]),
                "case_no": row["case_no"],
            })
        return index

    def _event(self, package_id: int, event_type: str, actor: str, detail: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO supplementary_package_events(package_id,event_type,actor,detail_json,created_at) "
            "VALUES(?,?,?,?,?)",
            (
                package_id, event_type, actor,
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
