import json
import uuid
from typing import Any

import aiosqlite

from ..common.types import (  # type: ignore
    AuditLogEntry,
    CensorResult,
    DBError,
    Message,
    RiskLevel,
)


class AuditLogMixin:
    """审计日志相关功能"""

    db: aiosqlite.Connection | None

    async def _create_tables(self) -> None:
        """
        创建审计日志表及其索引。
        如果表或索引已存在，则不会重复创建。
        """
        if not self.db:
            raise DBError("数据库未初始化")
        try:
            await self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                message_timestamp INTEGER NOT NULL,
                risk_level INTEGER NOT NULL,
                reason TEXT NOT NULL,
                result_extra TEXT,
                entry_extra TEXT
            )""")
            await self.db.execute(
                "CREATE INDEX IF NOT EXISTS idx_logs_source ON audit_logs(source)"
            )
            await self.db.execute(
                "CREATE INDEX IF NOT EXISTS idx_logs_time ON audit_logs(message_timestamp)"
            )
            await self.db.execute(
                "CREATE INDEX IF NOT EXISTS idx_logs_risk ON audit_logs(risk_level)"
            )
            await self.db.commit()
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"创建审计日志表失败: {e!s}")

    async def add_audit_log(
        self, result: CensorResult, extra: dict | None = None
    ) -> str:
        """
        添加一条审计日志记录。

        Args:
            result: 审查结果对象，包含消息内容、来源、时间戳、风险等级、原因和额外信息。
            extra: 审计日志条目的额外信息，可选。
        Returns:
            新添加的审计日志记录的ID。
        Raises:
            DBError: 数据库未初始化或查询失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        log_id = str(uuid.uuid4())
        reason_str = json.dumps(list(result.reason)) if result.reason else ""
        result_extra_str = json.dumps(result.extra) if result.extra else None
        entry_extra_str = json.dumps(extra) if extra else None

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO audit_logs
                    (id, content, source, message_timestamp, risk_level, reason, result_extra, entry_extra)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_id,
                        result.message.content,
                        result.message.source,
                        result.message.timestamp,
                        result.risk_level.value,
                        reason_str,
                        result_extra_str,
                        entry_extra_str,
                    ),
                )
                await self.db.commit()
                return log_id
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"添加审计日志失败: {e!s}")

    async def get_audit_logs_count(
        self,
        start_time: int | None = None,
        end_time: int | None = None,
        source: str | None = None,
        risk_level: RiskLevel | None = None,
    ) -> int:
        """
        获取符合条件的审计日志记录总数。

        Args:
            start_time: 起始时间戳，可选。
            end_time: 结束时间戳，可选。
            source: 消息来源，可选。
            risk_level: 风险等级，可选。

        Returns:
            符合条件的审计日志记录总数。

        Raises:
            DBError: 数据库未初始化或查询失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
        params: list[Any] = []
        if start_time:
            query += " AND message_timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND message_timestamp <= ?"
            params.append(end_time)
        if source:
            query += " AND source = ?"
            params.append(source)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level.value)
        try:
            async with self.db.execute(query, params) as cursor:
                result = await cursor.fetchone()
            return result[0] if result else 0
        except aiosqlite.Error as e:
            raise DBError(f"获取审计日志总数失败：{e!s}")

    async def get_audit_logs(
        self,
        start_time: int | None = None,
        end_time: int | None = None,
        source: str | None = None,
        risk_level: RiskLevel | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """
        获取符合条件的审计日志记录列表。

        Args:
            start_time: 起始时间戳，可选。
            end_time: 结束时间戳，可选。
            source: 消息来源，可选。
            risk_level: 风险等级，可选。
            limit: 返回的最大记录数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            符合条件的审计日志记录列表。

        Raises:
            DBError: 数据库未初始化或查询失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        query = """
            SELECT id, content, source, message_timestamp, risk_level, reason, result_extra, entry_extra
            FROM audit_logs WHERE 1=1
        """
        params: list[Any] = []
        if start_time:
            query += " AND message_timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND message_timestamp <= ?"
            params.append(end_time)
        if source:
            query += " AND source = ?"
            params.append(source)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level.value)
        query += " ORDER BY message_timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        try:
            async with self.db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
            return [self._parse_audit_log(row) for row in rows]
        except aiosqlite.Error as e:
            raise DBError(f"获取审计日志失败：{e!s}")

    async def search_audit_logs(
        self,
        search_term: str,
        start_time: int | None = None,
        end_time: int | None = None,
        source: str | None = None,
        risk_level: RiskLevel | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """
        搜索符合条件的审计日志记录列表。

        Args:
            search_term: 搜索关键词，将在内容和原因字段中进行搜索。
            start_time: 起始时间戳，可选。
            end_time: 结束时间戳，可选。
            source: 消息来源，可选。
            risk_level: 风险等级，可选。
            limit: 返回的最大记录数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            符合条件的审计日志记录列表。

        Raises:
            DBError: 数据库未初始化或查询失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        query = """
            SELECT id, content, source, message_timestamp, risk_level, reason, result_extra, entry_extra
            FROM audit_logs
            WHERE (content LIKE ? OR reason LIKE ?)
        """
        search_pattern = f"%{search_term}%"
        params: list[Any] = [search_pattern, search_pattern]
        if start_time:
            query += " AND message_timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND message_timestamp <= ?"
            params.append(end_time)
        if source:
            query += " AND source = ?"
            params.append(source)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level.value)
        query += " ORDER BY message_timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        try:
            async with self.db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
            return [self._parse_audit_log(row) for row in rows]
        except aiosqlite.Error as e:
            raise DBError(f"搜索审计日志失败：{e!s}")

    async def delete_audit_log(self, log_id: str) -> bool:
        """
        删除指定ID的审计日志记录。

        Args:
            log_id: 要删除的审计日志记录的ID。

        Returns:
            如果删除成功返回True，否则返回False。
        Raises:
            DBError: 数据库未初始化或删除失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        try:
            async with self.db.cursor() as cursor:
                await cursor.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
                deleted = cursor.rowcount > 0
                await self.db.commit()
                return deleted
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"删除审计日志失败：{e!s}")

    def _parse_audit_log(self, row) -> AuditLogEntry:
        """
        解析数据库查询结果行，将其转换为AuditLogEntry对象。

        Args:
            row: 数据库查询结果的一行数据。

        Returns:
            解析后的AuditLogEntry对象。
        """
        (
            log_id,
            content,
            source_str,
            message_ts,
            risk_level_value,
            reason_str,
            result_extra_str,
            entry_extra_str,
        ) = row

        try:
            reason_set = set(json.loads(reason_str)) if reason_str else set()
        except json.JSONDecodeError:
            reason_set = set()

        try:
            result_extra = json.loads(result_extra_str) if result_extra_str else None
        except json.JSONDecodeError:
            result_extra = None

        try:
            entry_extra = json.loads(entry_extra_str) if entry_extra_str else None
        except json.JSONDecodeError:
            entry_extra = None

        risk_level_enum = RiskLevel(risk_level_value)
        message = Message(content=content, source=source_str, timestamp=message_ts)
        censor_result = CensorResult(
            message=message,
            risk_level=risk_level_enum,
            reason=reason_set,
            extra=result_extra,
        )

        return AuditLogEntry(id=log_id, result=censor_result, extra=entry_extra)
