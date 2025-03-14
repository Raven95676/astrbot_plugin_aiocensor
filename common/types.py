import time
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    Fallback = -1  # 备用
    Pass = 0
    Review = 1
    Block = 2


@dataclass
class Message:
    """
    表示一条消息。

    Args:
        content (str): 消息内容。
        source (str): 消息来源。
        timestamp (Optional[int]): 消息的时间戳，默认为当前时间。
    """

    content: str
    source: str
    timestamp: int | None = None

    def __post_init__(self) -> None:
        self.timestamp = self.timestamp or int(time.time())


@dataclass
class CensorResult:
    """
    表示审查结果。

    Args:
        message (Message): 被审查的消息。
        risk_level (RiskLevel): 风险等级。
        reason (set[str]): 风险原因集合。
    """

    message: Message
    risk_level: RiskLevel
    reason: set[str]


@dataclass
class AuditLogEntry:
    """
    表示一条审计日志记录。

    Args:
        id (str): 审计日志的唯一标识符。
        result (CensorResult): 审查结果。
        updated_at (int): 记录更新时间戳。
    """

    id: str
    result: CensorResult
    updated_at: int


@dataclass
class SensitiveWordEntry:
    """
    表示一个敏感词条目。

    Args:
        id (str): 敏感词条目的唯一标识符。
        word (str): 敏感词。
        updated_at (int): 记录更新时间戳。
    """

    id: str
    word: str
    updated_at: int


@dataclass
class BlacklistEntry:
    """
    表示一个黑名单条目。

    Args:
        id (str): 黑名单条目的唯一标识符。
        identifier (str): 被加入黑名单的标识符。
        reason (Optional[str]): 加入黑名单的原因。
        updated_at (int): 记录更新时间戳。
    """

    id: str
    identifier: str
    reason: str | None
    updated_at: int


class DBError(Exception):
    """
    数据库异常类。

    当数据库操作失败时抛出此异常。

    Args:
        message (str): 描述数据库错误的消息。
    """

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.message}"


class CensorError(Exception):
    """
    审核异常类。

    当内容审核过程中发生错误时抛出此异常。

    Args:
        message (str): 描述审核错误的消息。
    """

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.message}"
