import uuid
import time
import aiosqlite
from common.types import BlacklistEntry, DBError # type: ignore


class BlacklistMixin:
    """黑名单相关功能"""

    db: aiosqlite.Connection | None

    async def _create_tables(self) -> None:
        """
        创建黑名单表。

        Raises:
            DBError: 数据库未初始化或创建表失败。
        """
        if not self.db:
            raise DBError("数据库未初始化")
        try:
            await self.db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id TEXT PRIMARY KEY,
                identifier TEXT UNIQUE NOT NULL,
                reason TEXT,
                updated_at INTEGER NOT NULL
            )""")
            await self.db.commit()
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"创建黑名单表失败: {e}")

    async def add_blacklist_entry(
        self, identifier: str, reason: str | None = None
    ) -> str:
        """
        添加一个黑名单条目。

        Args:
            identifier: 黑名单标识符，通常是用户ID或群组ID。
            reason: 添加到黑名单的原因，可选。

        Returns:
            新添加的黑名单条目的ID。

        Raises:
            DBError: 数据库未初始化或添加条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        entry_id = str(uuid.uuid4())
        current_time = int(time.time())
        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    "INSERT INTO blacklist (id, identifier, reason, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(identifier) DO UPDATE SET reason = ?, updated_at = ? RETURNING id",
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
        获取黑名单条目列表。

        Args:
            limit: 返回的最大条目数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            黑名单条目列表。

        Raises:
            DBError: 数据库未初始化或获取条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        try:
            async with self.db.execute(
                "SELECT id, identifier, reason, updated_at FROM blacklist ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()
            return [
                BlacklistEntry(
                    id=row[0], identifier=row[1], reason=row[2], updated_at=row[3]
                )
                for row in rows
            ]
        except aiosqlite.Error as e:
            raise DBError(f"获取黑名单条目失败：{e}")

    async def get_blacklist_entries_count(self) -> int:
        """
        获取黑名单条目的总数。

        Returns:
            黑名单条目的总数。

        Raises:
            DBError: 数据库未初始化或获取条目总数失败。
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
            search_term: 搜索关键词，将在标识符和原因字段中进行搜索。
            limit: 返回的最大条目数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            符合搜索条件的黑名单条目列表。

        Raises:
            DBError: 数据库未初始化或搜索条目失败。
        """
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        search_pattern = f"%{search_term}%"
        try:
            async with self.db.execute(
                "SELECT id, identifier, reason, updated_at FROM blacklist WHERE identifier LIKE ? OR reason LIKE ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (search_pattern, search_pattern, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()
            return [
                BlacklistEntry(
                    id=row[0], identifier=row[1], reason=row[2], updated_at=row[3]
                )
                for row in rows
            ]
        except aiosqlite.Error as e:
            raise DBError(f"搜索黑名单条目失败：{e}")

    async def delete_blacklist_entry(self, entry_id: str) -> bool:
        """
        删除一个黑名单条目。

        Args:
            entry_id: 要删除的黑名单条目的ID。

        Returns:
            如果删除成功返回True，否则返回False。

        Raises:
            DBError: 数据库未初始化或删除条目失败。
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
