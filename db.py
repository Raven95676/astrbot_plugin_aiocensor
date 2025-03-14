import json
import logging
import time
import uuid
from typing import Any

import aiosqlite
from .common.types import ( # type: ignore
    RiskLevel,
    AuditLogEntry,
    BlacklistEntry,
    CensorResult,
    Message,
    SensitiveWordEntry,
    DBError,
)

logger = logging.getLogger(__name__)


class DBManager:
    def __init__(self, db_path: str):
        self.db_path: str = db_path
        self.db: aiosqlite.Connection | None = None

    async def __aenter__(self) -> "DBManager":
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def initialize(self) -> None:
        """初始化数据库连接和表结构"""
        try:
            self.db = await aiosqlite.connect(self.db_path)
            await self.db.execute("PRAGMA foreign_keys = ON")
            await self.db.execute("PRAGMA journal_mode = WAL")
            await self._create_tables()
        except aiosqlite.Error as e:
            if self.db:
                await self.db.close()
                self.db = None
            raise DBError(f"无法连接到数据库: {e}")
        except Exception as e:
            if self.db:
                await self.db.close()
                self.db = None
            raise DBError(f"初始化数据库失败: {e}")

    async def _create_tables(self) -> None:
        """创建数据库表"""
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
                updated_at INTEGER NOT NULL
            )
            """)

            await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_time ON audit_logs(message_timestamp)
            """)

            await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_risk ON audit_logs(risk_level)
            """)

            await self.db.execute("""
            CREATE TABLE IF NOT EXISTS sensitive_words (
                id TEXT PRIMARY KEY,
                word TEXT UNIQUE NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """)

            await self.db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id TEXT PRIMARY KEY,
                identifier TEXT UNIQUE NOT NULL,
                reason TEXT,
                updated_at INTEGER NOT NULL
            )
            """)

            await self.db.commit()
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"创建数据库表失败: {e}")

    async def add_audit_log(self, result: CensorResult) -> str:
        """
        添加审计日志。

        Args:
            result (CensorResult): 审核结果。

        Returns:
            str: 审计日志ID。

        Raises:
            DBError: 数据库未初始化或连接已关闭，或添加审计日志失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        log_id = str(uuid.uuid4())
        reason_str = json.dumps(list(result.reason)) if result.reason else ""

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO audit_logs
                    (id, content, source, message_timestamp, risk_level, reason, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_id,
                        result.message.content,
                        result.message.source,
                        result.message.timestamp,
                        result.risk_level.value,
                        reason_str,
                        int(time.time()),
                    ),
                )
                await self.db.commit()
                return log_id
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"添加审计日志失败: {e}")

    async def get_audit_logs_count(
        self,
        start_time: int | None = None,
        end_time: int | None = None,
        source: str | None = None,
        risk_level: RiskLevel | None = None,
    ) -> int:
        """
        获取符合条件的审计日志总数。

        Args:
            start_time (int | None): 起始时间戳，默认为 None。
            end_time (int | None): 结束时间戳，默认为 None。
            source (str | None): 来源，默认为 None。
            risk_level (RiskLevel | None): 风险等级，默认为 None。

        Returns:
            int: 符合条件的审计日志总数。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取审计日志总数失败。
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
            raise DBError(f"获取审计日志总数失败：{e}")

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
        获取审计日志。

        Args:
            start_time (int | None): 起始时间戳，默认为 None。
            end_time (int | None): 结束时间戳，默认为 None。
            source (str | None): 来源，默认为 None。
            risk_level (RiskLevel | None): 风险等级，默认为 None。
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[AuditLogEntry]: 审计日志列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取审计日志失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        query = """
        SELECT id, content, source, message_timestamp, risk_level, reason, updated_at
        FROM audit_logs
        WHERE 1=1
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

            results: list[AuditLogEntry] = []
            for row in rows:
                (
                    log_id,
                    content,
                    source_str,
                    message_ts,
                    risk_level_value,
                    reason_str,
                    updated_at,
                ) = row

                try:
                    reason_set: set[str] = (
                        set(json.loads(reason_str)) if reason_str else set()
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"解析审计日志原因字段失败，ID={log_id}: {e}")
                    reason_set = set()

                risk_level_enum = RiskLevel(risk_level_value)

                message = Message(
                    content=content, source=source_str, timestamp=message_ts
                )
                censor_result = CensorResult(
                    message=message, risk_level=risk_level_enum, reason=reason_set
                )
                results.append(
                    AuditLogEntry(
                        id=log_id, result=censor_result, updated_at=updated_at
                    )
                )

            return results
        except aiosqlite.Error as e:
            raise DBError(f"获取审计日志失败：{e}")

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
        搜索审计日志。

        Args:
            search_term (str): 搜索关键词。
            start_time (int | None): 起始时间戳，默认为 None。
            end_time (int | None): 结束时间戳，默认为 None。
            source (str | None): 来源，默认为 None。
            risk_level (RiskLevel | None): 风险等级，默认为 None。
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[AuditLogEntry]: 审计日志列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或搜索审计日志失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        query = """
        SELECT id, content, source, message_timestamp, risk_level, reason, updated_at
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

            results: list[AuditLogEntry] = []
            for row in rows:
                (
                    log_id,
                    content,
                    source_str,
                    message_ts,
                    risk_level_value,
                    reason_str,
                    updated_at,
                ) = row

                try:
                    reason_set: set[str] = (
                        set(json.loads(reason_str)) if reason_str else set()
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"解析审计日志原因字段失败，ID={log_id}: {e}")
                    reason_set = set()

                risk_level_enum = RiskLevel(risk_level_value)

                message = Message(
                    content=content, source=source_str, timestamp=message_ts
                )
                censor_result = CensorResult(
                    message=message, risk_level=risk_level_enum, reason=reason_set
                )
                results.append(
                    AuditLogEntry(
                        id=log_id, result=censor_result, updated_at=updated_at
                    )
                )

            return results
        except aiosqlite.Error as e:
            raise DBError(f"搜索审计日志失败：{e}")

    async def delete_audit_log(self, log_id: str) -> bool:
        """
        删除审计日志条目。

        Args:
            log_id (str): 审计日志ID。

        Returns:
            bool: 是否成功删除。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或删除审计日志失败。
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
            raise DBError(f"删除审计日志失败：{e}")

    async def add_sensitive_word(self, word: str) -> str:
        """
        添加敏感词到数据库。

        Args:
            word (str): 敏感词。

        Returns:
            str: 敏感词ID。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或添加敏感词失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        word_id = str(uuid.uuid4())
        current_time = int(time.time())

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO sensitive_words (id, word, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(word) DO UPDATE SET
                        updated_at = ?
                    RETURNING id
                    """,
                    (word_id, word, current_time, current_time),
                )
                result = await cursor.fetchone()
                await self.db.commit()
                return result[0] if result else word_id
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"添加敏感词失败：{e}")

    async def get_sensitive_words(
        self, limit: int = 100, offset: int = 0
    ) -> list[SensitiveWordEntry]:
        """
        获取敏感词。

        Args:
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[SensitiveWordEntry]: 敏感词列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取敏感词失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.execute(
                "SELECT id, word, updated_at FROM sensitive_words ORDER BY word LIMIT ? OFFSET ?",
                (limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

            return [
                SensitiveWordEntry(id=row[0], word=row[1], updated_at=row[2])
                for row in rows
            ]
        except aiosqlite.Error as e:
            raise DBError(f"获取敏感词失败：{e}")

    async def get_sensitive_words_count(self) -> int:
        """
        获取敏感词总数。

        Returns:
            int: 敏感词总数。

        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取敏感词总数失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.execute(
                "SELECT COUNT(*) FROM sensitive_words"
            ) as cursor:
                result = await cursor.fetchone()
            return result[0] if result else 0
        except aiosqlite.Error as e:
            raise DBError(f"获取敏感词总数失败：{e}")

    async def search_sensitive_words(
        self, search_term: str, limit: int = 100, offset: int = 0
    ) -> list[SensitiveWordEntry]:
        """
        搜索敏感词。

        Args:
            search_term (str): 搜索关键词。
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[SensitiveWordEntry]: 敏感词列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或搜索敏感词失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        search_pattern = f"%{search_term}%"
        try:
            async with self.db.execute(
                "SELECT id, word, updated_at FROM sensitive_words WHERE word LIKE ? ORDER BY word LIMIT ? OFFSET ?",
                (search_pattern, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

            return [
                SensitiveWordEntry(id=row[0], word=row[1], updated_at=row[2])
                for row in rows
            ]
        except aiosqlite.Error as e:
            raise DBError(f"搜索敏感词失败：{e}")

    async def delete_sensitive_word(self, word_id: str) -> bool:
        """
        删除敏感词。

        Args:
            word_id (str): 敏感词ID。

        Returns:
            bool: 是否成功删除。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或删除敏感词失败.
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    "DELETE FROM sensitive_words WHERE id = ?", (word_id,)
                )
                deleted = cursor.rowcount > 0
                await self.db.commit()
                return deleted
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"删除敏感词失败：{e}")

    async def add_blacklist_entry(
        self, identifier: str, reason: str | None = None
    ) -> str:
        """
        添加条目到黑名单。

        Args:
            identifier (str): 黑名单标识符。
            reason (str | None): 添加原因，默认为 None。

        Returns:
            str: 黑名单条目ID。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或添加黑名单条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        entry_id = str(uuid.uuid4())
        current_time = int(time.time())

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO blacklist (id, identifier, reason, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(identifier) DO UPDATE SET
                        reason = ?,
                        updated_at = ?
                    RETURNING id
                    """,
                    (entry_id, identifier, reason, current_time, reason, current_time),
                )
                result = await cursor.fetchone()
                await self.db.commit()
                return result[0] if result else entry_id
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"添加黑名单条目失败：{e}")

    async def get_blacklist_entries(
        self, limit: int = 100, offset: int = 0
    ) -> list[BlacklistEntry]:
        """
        获取黑名单条目。

        Args:
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[BlacklistEntry]: 黑名单条目列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取黑名单条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.execute(
                "SELECT id, identifier, reason, updated_at FROM blacklist ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

            entries: list[BlacklistEntry] = []
            for row in rows:
                id_, identifier, reason, updated_at = row
                entries.append(
                    BlacklistEntry(
                        id=id_,
                        identifier=identifier,
                        reason=reason,
                        updated_at=updated_at,
                    )
                )

            return entries
        except aiosqlite.Error as e:
            raise DBError(f"获取黑名单条目失败：{e}")

    async def get_blacklist_entries_count(self) -> int:
        """
        获取黑名单条目总数。

        Returns:
            int: 黑名单条目总数。

        Raises:
            DBError: 数据库未初始化或连接已关闭，或获取黑名单条目总数失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.execute("SELECT COUNT(*) FROM blacklist") as cursor:
                result = await cursor.fetchone()
            return result[0] if result else 0
        except aiosqlite.Error as e:
            raise DBError(f"获取黑名单条目总数失败：{e}")

    async def search_blacklist(
        self, search_term: str, limit: int = 100, offset: int = 0
    ) -> list[BlacklistEntry]:
        """
        搜索黑名单条目。

        Args:
            search_term (str): 搜索关键词。
            limit (int): 最大返回数量，默认为 100。
            offset (int): 偏移量，默认为 0。

        Returns:
            list[BlacklistEntry]: 黑名单条目列表。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或搜索黑名单条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        search_pattern = f"%{search_term}%"
        try:
            async with self.db.execute(
                """
                SELECT id, identifier, reason, updated_at
                FROM blacklist
                WHERE identifier LIKE ? OR reason LIKE ?
                ORDER BY updated_at DESC LIMIT ? OFFSET ?
                """,
                (search_pattern, search_pattern, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

                entries: list[BlacklistEntry] = []
                for row in rows:
                    id_, identifier, reason, updated_at = row
                    entries.append(
                        BlacklistEntry(
                            id=id_,
                            identifier=identifier,
                            reason=reason,
                            updated_at=updated_at,
                        )
                    )
            return entries
        except aiosqlite.Error as e:
            raise DBError(f"搜索黑名单条目失败：{e}")

    async def delete_blacklist_entry(self, entry_id: str) -> bool:
        """
        通过ID删除黑名单条目。

        Args:
            entry_id (str): 黑名单条目ID。

        Returns:
            bool: 是否成功删除。
        Raises:
            DBError: 数据库未初始化或连接已关闭，或删除黑名单条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")

        try:
            async with self.db.cursor() as cursor:
                await cursor.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
                deleted = cursor.rowcount > 0
                await self.db.commit()
                return deleted
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"删除黑名单条目失败：{e}")

    async def close(self) -> None:
        """
        关闭数据库连接。

        Raises:
            DBError: 关闭数据库连接失败。

        """
        if self.db:
            try:
                await self.db.close()
                self.db = None
            except aiosqlite.Error as e:
                raise DBError(f"关闭数据库连接失败：{e}")
