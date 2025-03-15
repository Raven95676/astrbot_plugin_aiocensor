import uuid
import time
import aiosqlite
from common.types import SensitiveWordEntry, DBError # type: ignore



class SensitiveWordMixin:
    """敏感词相关功能"""

    db: aiosqlite.Connection | None
    async def _create_tables(self) -> None:
        if not self.db:
            raise DBError("数据库未初始化")
        try:
            await self.db.execute("""
            CREATE TABLE IF NOT EXISTS sensitive_words (
                id TEXT PRIMARY KEY,
                word TEXT UNIQUE NOT NULL,
                updated_at INTEGER NOT NULL
            )""")
            await self.db.commit()
        except aiosqlite.Error as e:
            await self.db.rollback()
            raise DBError(f"创建敏感词表失败: {e}")

    async def add_sensitive_word(self, word: str) -> str:
        if not self.db:
            raise DBError("数据库未初始化或连接已关闭")
        word_id = str(uuid.uuid4())
        current_time = int(time.time())
        try:
            async with self.db.cursor() as cursor:
                await cursor.execute(
                    "INSERT INTO sensitive_words (id, word, updated_at) VALUES (?, ?, ?) ON CONFLICT(word) DO UPDATE SET updated_at = ? RETURNING id",
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
