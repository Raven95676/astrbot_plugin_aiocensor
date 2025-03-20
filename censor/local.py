import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from kwmatcher import AhoMatcher

from ..common.interfaces import CensorBase  # type: ignore
from ..common.types import CensorError, RiskLevel  # type: ignore


class LocalCensor(CensorBase):
    __slots__ = (
        "_config",
        "_patterns",
        "_matcher",
        "_is_built",
        "_max_workers",
        "_executor",
        "_shutdown",
        "_lock",
    )

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._patterns = config.get("patterns", set())
        self._matcher = AhoMatcher(use_logic=config.get("use_logic", True))
        self._is_built = asyncio.Event()
        self._max_workers = config.get("max_threads", min(4, (os.cpu_count() or 1) * 2))
        self._executor: ThreadPoolExecutor | None = None
        self._shutdown = asyncio.Event()
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "LocalCensor":
        await self.build(self._patterns)
        return self

    async def build(self, patterns: set[str]) -> None:
        async with self._lock:
            if self._shutdown.is_set():
                await self._reinitialize()

            if self._is_built.is_set():
                return

            try:
                if not self._executor or self._executor._shutdown:
                    self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    self._executor, lambda: self._matcher.build(patterns)
                )
                self._is_built.set()
            except ValueError as e:
                raise CensorError(f"无效模式: {e}") from e
            except Exception as e:
                raise CensorError(f"构建失败: {e}") from e

    async def _reinitialize(self) -> None:
        self._shutdown.clear()
        self._is_built.clear()
        self._matcher = AhoMatcher(use_logic=self._config.get("use_logic", True))
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self) -> None:
        async with self._lock:
            if self._executor and not self._shutdown.is_set():
                self._executor.shutdown(wait=True)
                self._shutdown.set()
                self._is_built.clear()

    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        if not self._is_built.is_set():
            raise CensorError("状态机未构建")
        if self._shutdown.is_set():
            raise CensorError("实例正在关闭")

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor, lambda: self._matcher.find(text)
            )

            risk_words_set = result
            if risk_words_set:
                return (
                    RiskLevel.Block,
                    risk_words_set,
                )
            return RiskLevel.Pass, set()

        except Exception as e:
            raise CensorError(f"文本检测失败: {str(e)}")

    async def detect_image(self, image: str) -> tuple[RiskLevel, set[str]]:
        if self._shutdown.is_set():
            raise CensorError("实例正在关闭")

        return RiskLevel.Fallback, {"未实现本地图片审核"}
