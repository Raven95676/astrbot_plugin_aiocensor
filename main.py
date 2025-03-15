from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from .censor import LocalCensor # type: ignore
from .common import RiskLevel # type: ignore


@register(
    "astrbot_plugin_aiocensor", "Raven95676", "Astrbot综合内容安全+群管插件", "v0.1.0"
)
class MyPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    # 注册指令的装饰器。指令名为 helloworld。注册成功后，发送 `/helloworld` 就会触发这个指令，并回复 `你好, {user_name}!`
    @filter.command("1")
    async def helloworld(self, event: AstrMessageEvent):
        """123"""
        lcensor = LocalCensor()
        await lcensor.add_keywords({"原神"})
        message_str = event.message_str
        level, _ = await lcensor.detect_text(message_str)
        if level == RiskLevel.Block:
            yield event.plain_result("启动！")

    async def terminate(self):
        """可选择实现 terminate 函数，当插件被卸载/停用时会调用。"""
