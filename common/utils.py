import asyncio
from functools import wraps
from typing import Any, Awaitable, Callable, TypeVar

import aiohttp

from .types import CensorError

T = TypeVar("T")


def censor_retry(
    max_retries: int = 3,
    base_delay: float = 0.5,
):
    """
    审核重试装饰器。

    用于包装一个异步函数，使其在遇到特定异常时自动重试。

    Args:
        max_retries (int): 最大重试次数，默认为3。
        base_delay (float): 初始重试延迟时间（秒），默认为0.5秒。

    Returns:
        Callable[..., Awaitable[T]]: 包装后的异步函数。

    Raises:
        CensorError: 当达到最大重试次数或发生未知错误时抛出。
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except aiohttp.ClientError:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(base_delay * (2**attempt))
                        continue
                except Exception as e:
                    raise CensorError(f"发生未知错误: {e!s}")

            raise CensorError(f"请求失败，已达到最大重试次数 ({max_retries})")

        return wrapper

    return decorator
