import asyncio
import os
from typing import Any

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image, Plain
from astrbot.api.provider import ProviderRequest
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.event_message_type import EventMessageType

from .censor import AliyunCensor, LLMCensor, LocalCensor, TencentCensor  # type:ignore
from .censor_flow import CensorFlow  # type:ignore
from .common import RiskLevel, dispose_msg  # type:ignore
from .db import DBManager  # type:ignore


@register(
    "astrbot_plugin_aiocensor", "Raven95676", "Astrbot综合内容安全+群管插件", "v0.1.0"
)
class AIOCensor(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config

        self.censor_flow = CensorFlow(config)
        data_path = os.path.join(os.getcwd(), "data", "aiocensor")
        if not os.path.exists(data_path):
            os.makedirs(data_path)
        self.db_mgr = DBManager(os.path.join(data_path, "censor.db"))

    async def initialize(self):
        """初始化组件"""
        logger.debug("初始化组件")
        await self.db_mgr.initialize()
        black_list = await self.db_mgr.get_blacklist_entries(limit=0)
        await self.censor_flow.userid_censor.build(
            {entry.identifier for entry in black_list}
        )
        if hasattr(self.censor_flow.text_censor, "build"):
            sensitive_words = await self.db_mgr.get_sensitive_words(limit=0)
            await self.censor_flow.text_censor.build(
                {entry.word for entry in sensitive_words}
            )

    @filter.event_message_type(EventMessageType.ALL)
    async def is_baned(self, event: AstrMessageEvent):
        """黑名单判定"""

        if self.config.get("enable_blacklist"):
            res = await self.censor_flow.submit_userid(
                event.get_sender_id(), event.unified_msg_origin
            )
            if res.risk_level == RiskLevel.Block:
                a = await self.db_mgr.add_audit_log(res)
                event.stop_event()
                logger.debug(a)

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def group_censor(self, event: AstrMessageEvent):
        """群管功能"""
        if not self.config.get("enable_group_msg_censor"):
            return

        group_list = self.config.get("group_list", [])
        if not group_list or event.get_group_id() not in group_list:
            return

        for comp in event.message_obj.message:
            if isinstance(comp, Plain):
                res = await self.censor_flow.submit_text(
                    comp.text, event.unified_msg_origin
                )
                if res.risk_level != RiskLevel.Pass:
                    await self.db_mgr.add_audit_log(res)
                    if (
                        event.get_platform_name() == "aiocqhttp"
                        and res.risk_level == RiskLevel.Block
                    ):
                        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
                            AiocqhttpMessageEvent,
                        )

                        assert isinstance(event, AiocqhttpMessageEvent)
                        await dispose_msg(event=event, client=event.bot)
                    break

            if isinstance(comp, Image) and self.config.get("enable_image_censor"):
                logger.debug(comp)
                res = await self.censor_flow.submit_image(
                    comp.url, event.unified_msg_origin
                )
                if res.risk_level != RiskLevel.Pass:
                    await self.db_mgr.add_audit_log(res)
                    if (
                        event.get_platform_name() == "aiocqhttp"
                        and res.risk_level == RiskLevel.Block
                    ):
                        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
                            AiocqhttpMessageEvent,
                        )

                        assert isinstance(event, AiocqhttpMessageEvent)
                        await dispose_msg(event=event, client=event.bot)
                    break

    async def terminate(self):
        """清理资源"""
        # self.web_ui.close()
        await self.censor_flow.close()
        await self.db_mgr.close()
