from __future__ import annotations

import sqlite3

from app.core.clock import Clock
from app.forensics.cases import ForensicCaseService
from app.forensics.custody import CustodyService
from app.forensics.merges import CaseMergeService
from app.forensics.quality import ReleaseService, QualityService
from app.forensics.repository import ForensicRepository
from app.forensics.supplementary import SupplementaryService
from app.forensics.examinations import ExaminationService


class ForensicService:
    """把共享事务连接交给各业务边界，便于 API 与 CLI 原子调用。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.repository = ForensicRepository(connection)
        self.forensic_cases = ForensicCaseService(connection, clock)
        self.custody = CustodyService(connection, clock)
        self.examinations = ExaminationService(connection, clock)
        self.quality = QualityService(connection, clock)
        self.release = ReleaseService(connection, clock)
        self.supplementary = SupplementaryService(connection, clock)
        self.merges = CaseMergeService(connection, clock)

    def dashboard(self) -> dict:
        return {
            "forensic_cases": self.repository.count_table("forensic_cases"),
            "specimens": self.repository.count_table("specimens"),
            "storage_locations": self.repository.count_table("storage_locations"),
            "examinations": self.repository.count_table("examinations"),
            "review_schedules": self.repository.count_table("review_schedules"),
            "quality_alerts": self.repository.count_table("quality_alerts"),
            "release_requests": self.repository.count_table("release_requests"),
            "supplementary_packages": self.repository.count_table("supplementary_packages"),
            "case_merges": self.repository.count_table("case_merges"),
        }
