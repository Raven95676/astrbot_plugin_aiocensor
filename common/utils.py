import asyncio
import base64
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


def get_image_format(img_b64: str):
    data = base64.b64decode(img_b64)
    if data.startswith(b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"):
        return "png"
    elif data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    elif data.startswith(b"BM"):
        return "bmp"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    elif data.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    elif data.startswith(b"icns"):
        return "icns"
    elif (
        data.startswith(b"\x49\x49\x2a\x00")
        or data.startswith(b"\x4d\x4d\x00\x2a")
        or data.startswith(b"\x49\x49\x2b\x00")
        or data.startswith(b"\x4d\x4d\x00\x2b")
    ):
        return "tiff"
    elif data.startswith(b"\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a"):
        return "jp2"
    else:
        return None
