from contextlib import AbstractAsyncContextManager
from typing import Any

from astrbot.api import AstrBotConfig, logger

from .censor import AliyunCensor, LLMCensor, LocalCensor, TencentCensor  # type: ignore
from .common.interfaces import CensorBase  # type: ignore
from .common.types import CensorResult, Message  # type: ignore


class CensorFlow(AbstractAsyncContextManager):
    __slots__ = (
        "_text_censor",
        "_image_censor",
        "_userid_censor",
        "_config",
    )

    def __init__(self, config: AstrBotConfig) -> None:
        """
        初始化 CensorFlow 实例

        参数:
            config: AstrBotConfig 实例
        """
        self._config = config

        text_provider = config.get("text_censor_provider", "")
        image_provider = config.get("image_censor_provider", "")
        enable_image_censor = config.get("enable_image_censor", False)

        configs: dict[str, dict[str, Any]] = {
            "aliyun": {
                "key_id": config.get("aliyun", {}).get("key_id"),
                "key_secret": config.get("aliyun", {}).get("key_secret"),
            },
            "llm": {
                "model": config.get("llm", {}).get("model"),
                "base_url": config.get("llm", {}).get("base_url"),
                "api_key": config.get("llm", {}).get("api_key"),
            },
            "tencent": {
                "secret_id": config.get("tencent", {}).get("secret_id"),
                "secret_key": config.get("tencent", {}).get("secret_key"),
            },
            "local": {"use_logic": True},
        }

        self._text_censor = self._create_censor(text_provider, configs)

        self._image_censor = None
        if enable_image_censor and image_provider:
            self._image_censor = self._create_censor(image_provider, configs)

        self._userid_censor = LocalCensor({"use_logic": False})

    def _create_censor(
        self, provider: str, configs: dict[str, dict[str, Any]]
    ) -> CensorBase | None:
        """初始化一个Censor实例"""
        if not provider:
            return None

        try:
            if provider == "Aliyun":
                return AliyunCensor(configs["aliyun"])
            elif provider == "LLM":
                return LLMCensor(configs["llm"])
            elif provider == "Tencent":
                return TencentCensor(configs["tencent"])
            elif provider == "Local":
                logger.debug(configs["local"])
                return LocalCensor(configs["local"])
            else:
                logger.error(f"未知的审核提供商: {provider}")
                return None
        except Exception as e:
            logger.error(f"初始化审核提供商 '{provider}' 时出错: {e}")
            return None

    @property
    def text_censor(self) -> CensorBase:
        """返回文本审核实例"""
        return self._text_censor

    @property
    def image_censor(self) -> CensorBase | None:
        """返回图片审核实例"""
        return self._image_censor

    @property
    def userid_censor(self) -> CensorBase:
        """返回用户ID审核实例"""
        return self._userid_censor

    async def __aenter__(self) -> "CensorFlow":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def submit_text(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        提交文本审核任务

        参数:
            content: 待审核的文本内容
            source: 文本来源

        返回:
            审核结果
        """
        if not self._text_censor:
            raise RuntimeError("文本审核器未成功初始化，请检查配置")

        msg = Message(content, source)
        try:
            risk, reasons = await self._text_censor.detect_text(msg.content)
            return CensorResult(msg, risk, reasons)
        except Exception as e:
            logger.error(f"处理文本审核任务时发生错误: {e!s}")

    async def submit_image(
        self,
        content: str,
        source: str,
    ) -> CensorResult:
        """
        提交图片审核任务

        参数:
            content: 待审核的图片内容
            source: 图片来源

        返回:
            审核结果
        """
        if not self._image_censor:
            raise RuntimeError("图片审核未启用或未成功初始化，请检查配置")

        msg = Message(content, source)
        try:
            risk, reasons = await self._image_censor.detect_image(msg.content)
            return CensorResult(msg, risk, reasons)
        except Exception as e:
            logger.error(f"处理图片审核任务时发生错误: {e!s}")

    async def submit_userid(
        self,
        userid: str,
        source: str,
    ) -> CensorResult:
        """
        提交用户ID识别任务

        参数:
            userid: 待识别的用户ID
            source: 用户ID来源

        返回:
            识别结果
        """
        msg = Message(userid, source)
        try:
            risk, reasons = await self._userid_censor.detect_text(msg.content)
            return CensorResult(msg, risk, {f"黑名单用户{str(reasons)[1:-1]}"})
        except Exception as e:
            logger.error(f"处理用户ID识别任务时发生错误: {e!s}")

    async def close(self) -> None:
        """清理资源"""
        try:
            if self._text_censor:
                await self._text_censor.close()
            if self._image_censor and self._image_censor is not self._text_censor:
                await self._image_censor.close()
            if self._userid_censor:
                await self._userid_censor.close()
        except Exception as e:
            logger.error(f"关闭时出错: {e!s}")
