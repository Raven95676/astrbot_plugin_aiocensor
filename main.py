import os
import secrets
from multiprocessing import Process

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type:ignore

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image, Plain
from astrbot.api.provider import ProviderRequest
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.event_message_type import EventMessageType

from .censor_flow import CensorFlow  # type:ignore
from .common import RiskLevel, admin_check, dispose_msg  # type:ignore
from .db import DBManager  # type:ignore
from .webui import run_server  # type:ignore


@register(
    "astrbot_plugin_aiocensor", "Raven95676", "Astrbot综合内容安全+群管插件", "v0.0.3"
)
class AIOCensor(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.web_ui_process: Process | None = None
        self.scheduler: AsyncIOScheduler | None = None

        # 初始化内容审查流
        self.censor_flow = CensorFlow(config)
        data_path = os.path.join(os.getcwd(), "data", "aiocensor")
        os.makedirs(data_path, exist_ok=True)
        self.db_mgr = DBManager(os.path.join(data_path, "censor.db"))

    async def initialize(self):
        """初始化组件"""
        logger.debug("初始化 AIOCensor 组件")
        try:
            # 生成 Web UI 密钥（如果未设置）
            if not self.config["webui"].get("secret"):
                self.config["webui"]["secret"] = secrets.token_urlsafe(32)
                self.config.save_config()

            # 初始化数据库和审查器
            await self.db_mgr.initialize()
            await self._update_censors()

            # 设置定时任务，每 5 分钟更新审查器数据
            self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
            self.scheduler.add_job(
                self._update_censors,
                "interval",
                minutes=5,
                id="update_censors",
                misfire_grace_time=60,
            )
            self.scheduler.start()

            # 启动 Web UI 服务
            self.web_ui_process = Process(
                target=run_server,
                args=(
                    self.config["webui"]["secret"],
                    self.config["webui"]["password"],
                    self.config["webui"].get("host", "0.0.0.0"),
                    self.config["webui"].get("port", 9966),
                ),
                daemon=True,
            )
            self.web_ui_process.start()
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            raise

    async def _update_censors(self):
        """定期更新审查器数据"""
        try:
            black_list = await self.db_mgr.get_blacklist_entries()
            await self.censor_flow.userid_censor.build(
                {entry.identifier for entry in black_list}
            )
            if hasattr(self.censor_flow.text_censor, "build"):
                sensitive_words = await self.db_mgr.get_sensitive_words()
                await self.censor_flow.text_censor.build(
                    {entry.word for entry in sensitive_words}
                )
            logger.debug("审查器数据已更新")
        except Exception as e:
            logger.error(f"更新审查器数据失败: {e}")

    async def _handle_aiocqhttp_group_message(self, event: AstrMessageEvent, res):
        """处理 aiocqhttp 平台的群消息"""
        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
            AiocqhttpMessageEvent,
        )

        if not isinstance(event, AiocqhttpMessageEvent):
            return

        group_id = int(event.get_group_id())
        user_id = int(event.get_sender_id())
        self_id = int(event.get_self_id())
        message_id = int(event.message_obj.message_id)

        res.extra.update(
            {
                "group_id": group_id,
                "user_id": user_id,
                "self_id": self_id,
                "message_id": message_id,
            }
        )

        if (
            res.risk_level == RiskLevel.Block
            and self.config.get("enable_group_msg_censor")
            and not await admin_check(user_id, group_id, self_id, event.bot)
        ):
            try:
                await dispose_msg(
                    message_id=message_id,
                    group_id=group_id,
                    user_id=user_id,
                    self_id=self_id,
                    client=event.bot,
                )
            except Exception as e:
                logger.error(f"消息处置失败: {e}")

    async def handle_message(self, event: AstrMessageEvent):
        """核心消息内容审查逻辑"""
        try:
            # 检查黑名单（若启用）
            if self.config.get("enable_blacklist"):
                res = await self.censor_flow.submit_userid(
                    event.get_sender_id(), event.unified_msg_origin
                )
                if res.risk_level == RiskLevel.Block:
                    await self.db_mgr.add_audit_log(res)
                    event.stop_event()
                    return

            # 遍历消息组件进行审计
            for comp in event.message_obj.message:
                res = None
                if isinstance(comp, Plain):
                    res = await self.censor_flow.submit_text(
                        comp.text, event.unified_msg_origin
                    )
                elif isinstance(comp, Image) and self.config.get("enable_image_censor"):
                    res = await self.censor_flow.submit_image(
                        comp.url, event.unified_msg_origin
                    )
                else:
                    continue

                if res and res.risk_level != RiskLevel.Pass:
                    res.extra = {"user_id_str": event.get_sender_id()}
                    await self.db_mgr.add_audit_log(res)

                    if res.risk_level == RiskLevel.Block:
                        if (
                            event.get_platform_name() == "aiocqhttp"
                            and event.get_group_id()
                        ):
                            await self._handle_aiocqhttp_group_message(event, res)
                        else:
                            logger.warning("非 aiocqhttp 平台的群消息，无法自动处置")
                        event.stop_event()
                        break
        except Exception as e:
            logger.error(f"消息审查失败: {e}")

    @filter.on_decorating_result()
    async def on_decorating_result(self, event: AstrMessageEvent):
        """输出内容审查"""
        if self.config.get("enable_output_censor"):
            await self.handle_message(event)

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def group_censor(self, event: AstrMessageEvent):
        """群消息审查"""
        if not self.config.get("enable_group_msg_censor"):
            return
        group_list = self.config.get("group_list", [])
        if group_list and event.get_group_id() not in group_list:
            return
        await self.handle_message(event)

    @filter.event_message_type(EventMessageType.PRIVATE_MESSAGE)
    async def private_censor(self, event: AstrMessageEvent):
        """私聊消息审查"""
        if self.config.get("enable_private_msg_censor"):
            await self.handle_message(event)

    @filter.on_llm_request()
    async def on_llm_request(self, request: ProviderRequest, event: AstrMessageEvent):
        """LLM 请求前审查"""
        if not self.config.get("enable_llm_censor"):
            return
        try:
            # 审查提示文本
            res = await self.censor_flow.submit_text(
                request.prompt, event.unified_msg_origin
            )
            if res.risk_level != RiskLevel.Pass:
                await self.db_mgr.add_audit_log(res)
                event.stop_event()
                return

            # 审查图像 URL
            for image_url in request.image_urls:
                res = await self.censor_flow.submit_image(
                    image_url, event.unified_msg_origin
                )
                if res.risk_level != RiskLevel.Pass:
                    await self.db_mgr.add_audit_log(res)
                    event.stop_event()
                    return
        except Exception as e:
            logger.error(f"LLM 请求审查失败: {e}")

    async def terminate(self):
        """清理资源"""
        try:
            if self.scheduler:
                self.scheduler.shutdown()
            if self.web_ui_process:
                self.web_ui_process.terminate()
                self.web_ui_process.join(5)
            await self.censor_flow.close()
            await self.db_mgr.close()
            logger.debug("AIOCensor 资源已清理")
        except Exception as e:
            logger.error(f"资源清理失败: {e}")
