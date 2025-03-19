import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus

import aiohttp

from ..common.interfaces import CensorBase  # type: ignore
from ..common.types import CensorError, RiskLevel  # type: ignore
from ..common.utils import censor_retry  # type: ignore


class AliyunAuth:
    """
    阿里云内容安全API鉴权

    Args:
        key_id (str): Access Key ID
        key_secret (str): Access Key Secret
    """

    def __init__(self, key_id: str, key_secret: str):
        self.key_id = key_id
        self.key_secret = key_secret

    @staticmethod
    def _encode(s: Any) -> str:
        """
        对字符串进行URL编码。

        Args:
            s (Any): 需要编码的字符串。

        Returns:
            str: 编码后的字符串。
        """
        return (
            quote_plus(str(s))
            .replace("+", "%20")
            .replace("*", "%2A")
            .replace("%7E", "~")
        )

    def _generate_signature(self, method: str, params: dict[str, str]) -> str:
        """
        生成阿里云API请求签名。

        Args:
            method (str): HTTP请求方法，如"POST"。
            params (dict[str, str]): 请求参数字典。

        Returns:
            str: 生成的签名字符串。
        """
        sorted_params = sorted(params.items())
        canonical_query = "&".join(
            f"{self._encode(k)}={self._encode(v)}" for k, v in sorted_params
        )
        string_to_sign = f"{method}&{self._encode('/')}&{self._encode(canonical_query)}"
        key = f"{self.key_secret}&"
        signature = base64.b64encode(
            hmac.new(
                key.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("utf-8")
        return signature

    def prepare_request_params(
        self, action: str, service: str, service_params: dict[str, Any]
    ) -> dict[str, str]:
        """
        准备阿里云API请求参数。

        Args:
            action (str): API操作名称。
            service (str): 服务名称。
            service_params (dict[str, Any]): 服务参数字典。

        Returns:
            dict[str, str]: 准备好的请求参数字典。
        """
        params: dict[str, str] = {
            "Format": "JSON",
            "Version": "2022-03-02",
            "AccessKeyId": self.key_id,
            "SignatureMethod": "HMAC-SHA1",
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SignatureVersion": "1.0",
            "SignatureNonce": str(uuid.uuid4()),
            "Action": action,
            "Service": service,
            "ServiceParameters": json.dumps(service_params),
        }

        params["Signature"] = self._generate_signature("POST", params)
        return params


class AliyunCensor(CensorBase):
    """阿里云内容审核"""

    def __init__(self, config: dict[str, Any]) -> None:
        self.url: str = "https://green-cip.cn-shanghai.aliyuncs.com"
        self.auth = AliyunAuth(config["key_id"], config["key_secret"])
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        self.semaphore = asyncio.Semaphore(80)

    async def __aenter__(self) -> "AliyunCensor":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        await self.session.close()

    @staticmethod
    def _split_text(content: str) -> list[str]:
        """
        将文本内容分割成多个小块，每个小块不超过600个字符。
        用于处理阿里云文本审核接口对单次请求文本长度的限制。

        Args:
            content (str): 需要分割的文本内容。

        Returns:
            list[str]: 分割后的文本块列表。
        """
        if not content:
            return []
        chunks = []
        for i in range(0, len(content), 600):
            chunks.append(content[i : i + 600])
        return chunks

    @censor_retry(max_retries=3)
    async def _check_single_text(self, content: str) -> tuple[RiskLevel, set[str]]:
        """
        对单段文本进行内容审核。

        Args:
            content (str): 需要审核的文本内容。

        Returns:
            tuple[RiskLevel, set[str]]: 审核结果，包含风险等级和风险词集合。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """
        risk_words_set: set[str] = set()
        params = self.auth.prepare_request_params(
            action="TextModerationPlus",
            service="chat_detection_pro",
            service_params={"content": content},
        )
        async with self.semaphore:
            async with self.session.post(self.url, params=params) as response:
                response.raise_for_status()

                result = await response.json()
                data = result.get("Data")
                if not data:
                    raise CensorError(f"内容审核返回数据异常: {result!s}")

                risk_level = data.get("RiskLevel", "").lower()

                if reason_data := data.get("Result"):
                    for r_data in reason_data:
                        if "RiskWords" in r_data:
                            risk_words_list = [
                                word.strip() for word in r_data["RiskWords"].split(",")
                            ]
                            risk_words_set.update(risk_words_list)
                        if "CustomizedLibs" in reason_data:
                            customized_libs_list = [
                                word.strip()
                                for word in reason_data["CustomizedLibs"].split(",")
                            ]
                            risk_words_set.update(customized_libs_list)

                if risk_level == "none":
                    return RiskLevel.Pass, risk_words_set
                elif risk_level == "low":
                    return RiskLevel.Pass, risk_words_set
                elif risk_level == "block":
                    return RiskLevel.Block, risk_words_set
                else:
                    return RiskLevel.Review, risk_words_set

    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """
        对文本进行内容审核，如果文本长度超过600个字符，则会进行分段审核。

        Args:
            text (str): 需要审核的文本内容。

        Returns:
            tuple[RiskLevel, set[str]]: 审核结果，包含最高风险等级和所有风险词集合。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """
        try:
            if not text:
                return RiskLevel.Pass, set()

            if len(text) <= 600:
                return await self._check_single_text(text)

            chunks = self._split_text(text)
            tasks = [self._check_single_text(chunk) for chunk in chunks]
            results = await asyncio.gather(*tasks)

            highest_risk_level = RiskLevel.Pass
            all_risk_words = set()

            for risk_level, words in results:
                if risk_level.value > highest_risk_level.value:
                    highest_risk_level = risk_level

                all_risk_words.update(words)

            return highest_risk_level, all_risk_words

        except Exception as e:
            raise CensorError(f"内容审核过程中发生异常: {e!s}")

    @censor_retry(max_retries=3)
    async def detect_image(self, image) -> tuple[RiskLevel, set[str]]: # type: ignore
        """
        对图片进行内容审核。

        Args:
            image (str): 需要审核的图片URL。

        Returns:
            tuple[RiskLevel, set[str]]: 审核结果，包含风险等级和风险描述集合。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """
        reason_words_set: set[str] = set()

        if image.startswith("base64://"):
            return RiskLevel.Fallback, {"接口暂不支持base64图片"}

        if not image.startswith("http"):
            raise CensorError("预期外的输入")

        params = self.auth.prepare_request_params(
            action="ImageModeration",
            service="baselineCheck",
            service_params={
                "imageUrl": image,
                "infoType": "customImage,textInImage",
            },
        )
        async with self.semaphore:
            async with self.session.post(self.url, params=params) as response:
                response.raise_for_status()

                result = await response.json()
                data = result.get("Data")
                if not data:
                    raise CensorError(f"内容审核返回数据异常: {result!s}")

                risk_level = data.get("RiskLevel", "").lower()
                if reason_data := data.get("Result"):
                    for item in reason_data:
                        if description := item.get("Description"):
                            reason_words_set.add(description)

                if risk_level == "none":
                    return RiskLevel.Pass, reason_words_set
                elif risk_level == "low":
                    return RiskLevel.Pass, reason_words_set
                elif risk_level == "block":
                    return RiskLevel.Block, reason_words_set
                else:
                    return RiskLevel.Review, reason_words_set
