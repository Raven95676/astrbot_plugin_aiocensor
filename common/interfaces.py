from abc import abstractmethod
from contextlib import AbstractAsyncContextManager

from .types import RiskLevel


class CensorBase(AbstractAsyncContextManager):
    """Censor抽象基类"""

    @abstractmethod
    async def __aenter__(self):
        return self

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @abstractmethod
    async def close(self) -> None:
        """
        关闭Censor实例。
        """
        pass

    @abstractmethod
    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """
        检测文本内容是否合规。

        Args:
            text (str): 需要检测的文本内容。

        Returns:
            tuple[RiskLevel, set[str]]: 包含风险等级和风险原因的元组。
        """
        pass

    @abstractmethod
    async def detect_image(self, image: str) -> tuple[RiskLevel, set[str]]:
        """
        检测图片内容是否合规。

        Args:
            image (str): 需要检测的图片内容，可以是URL或base64编码的字符串。

        Returns:
            tuple[RiskLevel, set[str]]: 包含风险等级和风险原因的元组。
        """
        pass
