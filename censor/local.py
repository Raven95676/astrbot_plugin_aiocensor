import asyncio
import logging
from typing import Any

from ..common.types import RiskLevel  # type: ignore
from ..common.interfaces import CensorBase  # type: ignore

logger = logging.getLogger(__name__)


class LocalCensor(CensorBase):
    def __init__(
        self,
        config: dict[str, Any],
    ):
        """
        初始化本地审查器。

        Args:
            config (dict[str, Any]): 配置字典，包含keywords等参数
        """
        keywords = config.get("keywords", set())
        if keywords:
            self.keywords = set(keywords)
            self.dfa = self._build_dfa(self.keywords)
        else:
            self.keywords = set()
            self.dfa = {}
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        """异步上下文管理器的进入方法"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器的退出方法"""
        await self.close()

    async def close(self):
        """关闭审查器"""
        pass

    @staticmethod
    def _build_dfa(keywords: set[str]) -> dict:
        """构建字典树"""
        root: dict[str, Any] = {}
        for keyword in keywords:
            if not keyword:
                continue

            node = root
            for char in keyword:
                node = node.setdefault(char, {})
            node["is_end"] = True
        return root

    def _search_text(self, text: str) -> set[str]:
        """
        在文本中搜索关键字。

        Args:
            text (str): 要搜索的文本。

        Returns:
            set[str]: 找到的关键字集合。
        """
        matched_keywords = set()
        for i in range(len(text)):
            node = self.dfa
            for j in range(i, len(text)):
                char = text[j]
                if char in node:
                    node = node[char]
                    if "is_end" in node:
                        matched_keywords.add(text[i : j + 1])
                else:
                    break
        return matched_keywords

    async def add_keywords(self, new_keywords: set[str]) -> bool:
        """
        添加新的关键字。

        Args:
            new_keywords (set[str]): 要添加的关键字集合。

        Returns:
            bool: 如果成功添加并更新了DFA，则返回True，否则返回False。
        """
        async with self.lock:
            self.keywords.update(new_keywords)
            self.dfa = self._build_dfa(self.keywords)
            return True

    async def remove_keywords(self, keywords_to_remove: set[str]) -> bool:
        """
        移除指定的关键字。

        Args:
            keywords_to_remove (set[str]): 要移除的关键字集合。

        Returns:
            bool: 如果成功移除并更新了DFA，则返回True，否则返回False。
        """
        async with self.lock:
            original_size = len(self.keywords)
            self.keywords -= keywords_to_remove
            if len(self.keywords) < original_size:
                self.dfa = self._build_dfa(self.keywords)
                return True
            return False

    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """
        检测文本内容是否包含敏感词。

        Args:
            text (str): 要检测的文本。

        Returns:
            tuple[RiskLevel, set[str]]: 包含风险等级和找到的敏感词集合的元组。
        """
        async with self.lock:
            if not self.dfa:
                return RiskLevel.Review, {"加载失败"}

            keywords_found = self._search_text(text)
            return (
                (RiskLevel.Block, keywords_found)
                if keywords_found
                else (RiskLevel.Pass, set())
            )

    async def detect_image(self, image: str) -> tuple[RiskLevel, set[str]]:
        """
        检测图片内容是否合规。

        Args:
            image (str): 要检测的图片，目前未实现本地图片审核。

        Returns:
            tuple[RiskLevel, set[str]]: 包含风险等级和错误信息的元组。
        """
        logger.warning("未实现本地图片审核")
        return RiskLevel.Fallback, {"未实现本地图片审核"}
