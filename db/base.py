import aiosqlite
from common.types import DBError # type: ignore


class BaseDBMixin:
    """基础数据库Mixin"""

    def __init__(self, db_path: str):
        self.db_path: str = db_path
        self.db: aiosqlite.Connection | None = None

    async def __aenter__(self) -> "BaseDBMixin":
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def initialize(self) -> None:
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

    async def _create_tables(self):
        raise NotImplementedError

    async def close(self) -> None:
        if self.db:
            try:
                await self.db.close()
                self.db = None
            except aiosqlite.Error as e:
                raise DBError(f"关闭数据库连接失败：{e}")
