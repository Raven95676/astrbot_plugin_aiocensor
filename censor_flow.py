import asyncio
import logging
from asyncio import CancelledError
from contextlib import AbstractAsyncContextManager
from typing import Any, Callable, Coroutine, Optional, Union

from .common.types import CensorResult, Message, RiskLevel # type: ignore
from .common.interfaces import CensorBase # type: ignore

logger = logging.getLogger(__name__)


class CensorFlow(AbstractAsyncContextManager):
    def __init__(
        self,
        text_censor: CensorBase,
        image_censor: CensorBase | None = None,
        num_workers: int = 5,
    ) -> None:
        """
        初始化 CensorFlow 实例。

        Args:
            text_censor: 用于文本审核的 CensorBase 实例。
            image_censor: 用于图片审核的 CensorBase 实例，默认为 text_censor。
            num_workers: 工作线程数量，默认为 5。
        """
        self.text_censor: CensorBase = text_censor
        self.image_censor: CensorBase = image_censor or text_censor
        self.num_workers: int = num_workers

        self.text_queue: asyncio.Queue = asyncio.Queue()
        self.image_queue: asyncio.Queue = asyncio.Queue()

        self._tasks: list[asyncio.Task] = []
        self._shutdown: asyncio.Event = asyncio.Event()
        self._all_tasks_done: asyncio.Event = asyncio.Event()

    async def __aenter__(self) -> "CensorFlow":
        await self._start_workers()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def _start_workers(self) -> None:
        """初始化Worker"""
        for i in range(self.num_workers):
            self._tasks.append(
                asyncio.create_task(
                    self._worker(
                        self.text_queue,
                        self.text_censor.detect_text,
                        f"text-worker-{i}",
                    )
                )
            )

            self._tasks.append(
                asyncio.create_task(
                    self._worker(
                        self.image_queue,
                        self.image_censor.detect_image,
                        f"image-worker-{i}",
                    )
                )
            )

    async def _worker(
        self,
        queue: asyncio.Queue,
        detector: Callable[[str], Coroutine[Any, Any, tuple[RiskLevel, set[str]]]],
        name: str,
    ) -> None:
        """
        通用的工作线程函数。

        Args:
            queue: 任务队列。
            detector: 审核函数。
            name: 工作线程名称。
        """

        logger.debug(f"{name} 已启动")
        try:
            while not self._shutdown.is_set() or not queue.empty():
                try:
                    msg, future, callback = await queue.get()

                    try:
                        risk, reasons = await detector(msg.content)
                        result: CensorResult = CensorResult(msg, risk, reasons)

                        if not future.done():
                            future.set_result(result)

                        if callback:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(result)
                            else:
                                callback(result)
                    except Exception as e:
                        if not future.done():
                            future.set_exception(e)
                        logger.error(f"{name} 处理时发生错误: {e}")
                    finally:
                        queue.task_done()
                except Exception as e:
                    logger.error(f"{name} 处理时发生错误: {e}")
                    await asyncio.sleep(0.01)
        except CancelledError:
            logger.debug(f"{name} 已取消")
        finally:
            logger.debug(f"{name} 已退出")

    async def submit_text(
        self,
        content: str,
        source: str,
        callback: Optional[
            Union[
                Callable[[CensorResult], Any],
                Callable[[CensorResult], Coroutine[Any, Any, Any]],
            ]
        ] = None,
    ) -> CensorResult:
        """
        提交文本审核任务。

        Args:
            content: 待审核的文本内容。
            source: 文本来源。
            callback: 审核结果回调函数，可选。

        Returns:
            审核结果。
        """
        msg: Message = Message(content, source)
        future: asyncio.Future[CensorResult] = asyncio.Future()
        await self.text_queue.put((msg, future, callback))
        return await future

    async def submit_image(
        self,
        content: str,
        source: str,
        callback: Optional[
            Union[
                Callable[[CensorResult], Any],
                Callable[[CensorResult], Coroutine[Any, Any, Any]],
            ]
        ] = None,
    ) -> CensorResult:
        """
        提交图片审核任务。

        Args:
            content: 待审核的图片内容。
            source: 图片来源。
            callback: 审核结果回调函数，可选。

        Returns:
            审核结果。
        """
        msg: Message = Message(content, source)
        future: asyncio.Future[CensorResult] = asyncio.Future()
        await self.image_queue.put((msg, future, callback))
        return await future

    async def close(self, timeout: float = 10) -> None:
        """
        关闭 CensorFlow 实例，清理资源。

        Args:
            timeout: 等待队列处理完成的超时时间，默认为 10 秒。
        """
        self._shutdown.set()


        pending_queues = []
        for q in [self.text_queue, self.image_queue]:
            if not q.empty():
                pending_queues.append(q.join())

        if pending_queues:
            try:
                await asyncio.wait_for(asyncio.gather(*pending_queues), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("队列处理超时，可能有部分任务未完成")

        for t in self._tasks:
            if not t.done():
                t.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._all_tasks_done.set()

        try:
            await self.text_censor.close()

            if self.image_censor is not self.text_censor:
                await self.image_censor.close()

        except Exception as e:
            logger.error(f"关闭时发生错误: {e}")
