from contextlib import AbstractAsyncContextManager
from typing import Any

from astrbot.api import logger

from .common.interfaces import CensorBase  # type: ignore
from .common.types import CensorResult, Message  # type: ignore


class CensorFlow(AbstractAsyncContextManager):
    __slots__ = ("_text_censor", "_image_censor", "_userid_censor", "_is_running")

    def __init__(
        self,
        text_censor: CensorBase,
        image_censor: CensorBase | None = None,
        userid_censor: CensorBase | None = None,
    ) -> None:
        """
        初始化 CensorFlow 实例。

        参数:
            text_censor: 用于文本审核的 CensorBase 实例。
            image_censor: 用于图片审核的 CensorBase 实例，默认为 text_censor。
            userid_censor: 用于用户ID黑名单校验的 CensorBase 实例，默认为 text_censor。
        """
        self._text_censor = text_censor
        self._image_censor = image_censor or text_censor
        self._userid_censor = userid_censor or text_censor
        self._is_running = False

    @property
    def is_running(self) -> bool:
        """返回实例是否正在运行"""
        return self._is_running

    @property
    def text_censor(self) -> CensorBase:
        """返回文本审核实例"""
        return self._text_censor

    @property
    def image_censor(self) -> CensorBase:
        """返回图片审核实例"""
        return self._image_censor

    @property
    def userid_censor(self) -> CensorBase:
        """返回用户ID识别实例"""
        return self._userid_censor

    async def __aenter__(self) -> "CensorFlow":
        self._is_running = True
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def _process_task(
        self,
        msg: Message,
        detector: Any,
    ) -> CensorResult:
        """处理单个审核任务。"""
        try:
            risk, reasons = await detector(msg.content)
            return CensorResult(msg, risk, reasons)
        except Exception as e:
            logger.error(f"处理错误: {e!s}", exc_info=True)
            raise

    async def submit_text(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        提交文本审核任务。

        参数:
            content: 待审核的文本内容。
            source: 文本来源。

        返回:
            审核结果。
        """
        if not self._is_running:
            raise RuntimeError("CensorFlow 未运行")

        msg = Message(content, source)
        return await self._process_task(msg, self._text_censor.detect_text)

    async def submit_image(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        提交图片审核任务。

        参数:
            content: 待审核的图片内容。
            source: 图片来源。

        返回:
            审核结果。
        """
        if not self._is_running:
            raise RuntimeError("CensorFlow 未运行")

        msg = Message(content, source)
        return await self._process_task(msg, self._image_censor.detect_image)

    async def submit_userid(
        self,
        userid: str,
        source: str,
    ) -> CensorResult:
        """
        提交用户ID识别任务。

        参数:
            userid: 待识别的用户ID。
            source: 用户ID来源。

        返回:
            识别结果。
        """
        if not self._is_running:
            raise RuntimeError("CensorFlow 未运行")

        msg = Message(userid, source)
        return await self._process_task(msg, self._userid_censor.detect_text)

    async def close(self) -> None:
        """关闭 CensorFlow 实例，清理资源。"""
        if not self._is_running:
            return

        self._is_running = False
        try:
            await self._text_censor.close()
            if self._image_censor is not self._text_censor:
                await self._image_censor.close()
            if self._userid_censor is not self._text_censor:
                await self._userid_censor.close()
        except Exception as e:
            logger.error(f"关闭时出错: {e}")
