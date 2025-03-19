import asyncio
import logging
import os
from asyncio import CancelledError
from contextlib import AbstractAsyncContextManager
from typing import Any, Callable, Coroutine, Optional, Union

from .common.interfaces import CensorBase  # type: ignore
from .common.types import CensorResult, Message, RiskLevel  # type: ignore

logger = logging.getLogger(__name__)


class CensorFlow(AbstractAsyncContextManager):
    def __init__(
        self,
        text_censor: CensorBase,
        image_censor: CensorBase | None = None,
        username_censor: CensorBase | None = None,
        num_workers: int | None = None,
    ) -> None:
        """
        初始化 CensorFlow 实例。

        Args:
            text_censor: 用于文本审核的 CensorBase 实例。
            image_censor: 用于图片审核的 CensorBase 实例，默认为 text_censor。
            username_censor: 用于用户名黑名单校验的 CensorBase 实例，默认为 text_censor。
        """
        self._initialize(text_censor, image_censor, username_censor, num_workers)

    def _initialize(
        self,
        text_censor: CensorBase,
        image_censor: CensorBase | None = None,
        username_censor: CensorBase | None = None,
        num_workers: int | None = None,
    ) -> None:
        """初始化 CensorFlow 实例配置"""
        self.text_censor: CensorBase = text_censor
        self.image_censor: CensorBase = image_censor or text_censor
        self.username_censor: CensorBase = username_censor or text_censor
        self.num_workers: int = num_workers or min(5, (os.cpu_count() or 1) * 2)

        self.text_queue: asyncio.Queue = asyncio.Queue()
        self.image_queue: asyncio.Queue = asyncio.Queue()
        self.username_queue: asyncio.Queue = asyncio.Queue()

        self._tasks: list[asyncio.Task] = []
        self._shutdown: asyncio.Event = asyncio.Event()
        self._all_tasks_done: asyncio.Event = asyncio.Event()
        self._is_running: bool = False

    async def __aenter__(self) -> "CensorFlow":
        if not self._is_running:
            await self._start_workers()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def _start_workers(self) -> None:
        """初始化Worker"""
        if self._is_running:
            return

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

            self._tasks.append(
                asyncio.create_task(
                    self._worker(
                        self.username_queue,
                        self.username_censor.detect_text,
                        f"username-worker-{i}",
                    )
                )
            )

        self._is_running = True
        self._shutdown.clear()
        self._all_tasks_done.clear()

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

                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(result)
                            else:
                                callback(result)
                        except Exception as e:
                            logger.error(f"回调错误在 {name}: {e}", exc_info=True)
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

    async def submit_username(
        self,
        username: str,
        source: str,
        callback: Optional[
            Union[
                Callable[[CensorResult], Any],
                Callable[[CensorResult], Coroutine[Any, Any, Any]],
            ]
        ] = None,
    ) -> CensorResult:
        """
        提交用户名审核任务，检查是否在黑名单中。

        Args:
            username: 待审核的用户名。
            source: 用户名来源。
            callback: 审核结果回调函数，可选。

        Returns:
            审核结果。
        """
        msg: Message = Message(username, source)
        future: asyncio.Future[CensorResult] = asyncio.Future()
        await self.username_queue.put((msg, future, callback))
        return await future

    async def close(self, timeout: float = 10) -> None:
        """
        关闭 CensorFlow 实例，清理资源。

        Args:
            timeout: 等待队列处理完成的超时时间，默认为 10 秒。
        """
        if not self._is_running:
            return

        self._shutdown.set()

        pending_queues = []
        for q in [self.text_queue, self.image_queue, self.username_queue]:
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

        self._tasks.clear()
        self._all_tasks_done.set()
        self._is_running = False

        try:
            await self.text_censor.close()

            if self.image_censor is not self.text_censor:
                await self.image_censor.close()

            if (
                self.username_censor is not self.text_censor
                and self.username_censor is not self.image_censor
            ):
                await self.username_censor.close()

        except Exception as e:
            logger.error(f"关闭时发生错误: {e}")

    async def reload_censors(
        self,
        text_censor: CensorBase | None = None,
        image_censor: CensorBase | None = None,
        username_censor: CensorBase | None = None,
        num_workers: int | None = None,
    ) -> None:
        """
        重载审核器

        Args:
            text_censor: 新的文本审核器，None表示保持不变
            image_censor: 新的图片审核器，None表示保持不变
            username_censor: 新的用户名审核器，None表示保持不变
        """
        was_running = self._is_running

        if was_running:
            await self.close()

        new_text_censor = text_censor or self.text_censor
        new_image_censor = image_censor or self.image_censor
        new_username_censor = username_censor or self.username_censor

        self._initialize(
            new_text_censor, new_image_censor, new_username_censor, num_workers
        )

        if was_running:
            await self._start_workers()

    def get_text_censor(self) -> CensorBase:
        """获取当前的文本审核器"""
        return self.text_censor

    def get_image_censor(self) -> CensorBase:
        """获取当前的图片审核器"""
        return self.image_censor

    def get_username_censor(self) -> CensorBase:
        """获取当前的用户名审核器"""
        return self.username_censor

    def is_running(self) -> bool:
        """返回当前服务是否运行中"""
        return self._is_running
