import asyncio
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp

from ..common.interfaces import CensorBase  # type: ignore
from ..common.types import CensorError, RiskLevel  # type: ignore
from ..common.utils import censor_retry  # type: ignore


class TencentAuth:
    """腾讯云内容安全API鉴权"""

    __slots__ = ("_secret_id", "_secret_key")

    def __init__(self, secret_id: str, secret_key: str):
        self._secret_id = secret_id
        self._secret_key = secret_key

    def _generate_signature(
        self,
        service: str,
        host: str,
        action: str,
        payload: str,
    ) -> dict[str, Any]:
        """
        生成腾讯云API请求签名。

        Args:
            service (str): 腾讯云服务名称，例如 "tms" 或 "ims"。
            host (str): 腾讯云服务的主机地址，例如 "tms.tencentcloudapi.com"。
            action (str): 腾讯云API操作名称，例如 "TextModeration"。
            payload (str): 请求的JSON负载数据。

        Returns:
            dict[str, Any]: 包含签名信息的字典，包括：
                - authorization (str): 签名授权字符串。
                - timestamp (int): 时间戳。
        """
        timestamp = int(time.time())
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        http_request_method = "POST"
        canonical_uri = "/"
        canonical_querystring = ""
        ct = "application/json; charset=utf-8"
        canonical_headers = (
            f"content-type:{ct}\nhost:{host}\nx-tc-action:{action.lower()}\n"
        )
        signed_headers = "content-type;host;x-tc-action"
        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (
            http_request_method
            + "\n"
            + canonical_uri
            + "\n"
            + canonical_querystring
            + "\n"
            + canonical_headers
            + "\n"
            + signed_headers
            + "\n"
            + hashed_request_payload
        )

        credential_scope = f"{date}/{service}/tc3_request"
        hashed_canonical_request = hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest()
        string_to_sign = (
            "TC3-HMAC-SHA256"
            + "\n"
            + str(timestamp)
            + "\n"
            + credential_scope
            + "\n"
            + hashed_canonical_request
        )

        secret_date = hmac.new(
            f"TC3{self._secret_key}".encode("utf-8"),
            date.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        secret_service = hmac.new(
            secret_date, service.encode("utf-8"), hashlib.sha256
        ).digest()

        secret_signing = hmac.new(
            secret_service, "tc3_request".encode("utf-8"), hashlib.sha256
        ).digest()

        signature = hmac.new(
            secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        authorization = (
            "TC3-HMAC-SHA256 "
            + f"Credential={self._secret_id}/{credential_scope}, "
            + f"SignedHeaders={signed_headers}, "
            + f"Signature={signature}"
        )

        return {
            "authorization": authorization,
            "timestamp": timestamp,
            "version": "2020-12-29",
            "host": host,
            "action": action,
        }

    def prepare_request_headers(
        self,
        service: str,
        host: str,
        action: str,
        payload: str,
    ) -> dict[str, str]:
        """
        准备腾讯云API请求头。

        Args:
            service (str): 腾讯云服务名称，例如 "tms" 或 "ims"。
            host (str): 腾讯云服务的主机地址，例如 "tms.tencentcloudapi.com"。
            action (str): 腾讯云API操作名称，例如 "TextModeration"。
            payload (str): 请求的JSON负载数据。

        Returns:
            dict[str, str]: 包含请求头的字典，包括签名信息、内容类型、主机、区域、操作、时间戳和版本。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """
        signature_info = self._generate_signature(
            service,
            host,
            action,
            payload,
        )

        headers = {
            "Authorization": signature_info["authorization"],
            "Content-Type": "application/json; charset=utf-8",
            "Host": signature_info["host"],
            "X-TC-Region": "ap-guangzhou",
            "X-TC-Action": signature_info["action"],
            "X-TC-Timestamp": str(signature_info["timestamp"]),
            "X-TC-Version": signature_info["version"],
        }

        return headers


class TencentCensor(CensorBase):
    """腾讯云内容审核"""

    __slots__ = ("_text_url", "_image_url", "_auth", "_session", "_semaphore")

    def __init__(self, config: dict[str, Any]) -> None:
        self._text_url = "https://tms.tencentcloudapi.com"
        self._image_url = "https://ims.tencentcloudapi.com"
        self._auth = TencentAuth(config["secret_id"], config["secret_key"])
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        self._semaphore = asyncio.Semaphore(80)

    async def __aenter__(self) -> "TencentCensor":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        await self._session.close()

    @staticmethod
    def _split_text(content: str) -> list[str]:
        """
        将文本内容分割成多个小块，每个小块不超过10000个字符。
        用于处理腾讯云文本审核接口对单次请求文本长度的限制。

        Args:
            content (str): 需要分割的文本内容。

        Returns:
            list[str]: 分割后的文本块列表。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """
        if not content:
            return []
        chunks = []
        for i in range(0, len(content), 10000):
            chunks.append(content[i : i + 10000])
        return chunks

    @censor_retry(max_retries=3)
    async def _check_single_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """
        对单段文本进行内容审核。

        Args:
            text (str): 需要审核的文本内容。

        Returns:
            tuple[RiskLevel, set[str]]: 审核结果，包含风险等级和风险词集合。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """

        risk_words_set: set[str] = set()
        payload = json.dumps(
            {"Content": str(base64.b64encode(text.encode("utf-8")).decode("utf-8"))}
        )

        headers = self._auth.prepare_request_headers(
            service="tms",
            host="tms.tencentcloudapi.com",
            action="TextModeration",
            payload=payload,
        )
        async with self._semaphore:
            async with self._session.post(
                self._text_url, headers=headers, data=payload
            ) as response:
                response.raise_for_status()
                result = await response.json()
                res = result["Response"]

                if errmsg := res.get("Error"):
                    raise CensorError(f"内容审核请求异常: {errmsg.get('Message')!s}")

                risk_level = res.get("Suggestion", "").lower()
                risk_words_set.add(res.get("Label", ""))

                if kws := res.get("Keywords"):
                    for kw in kws:
                        risk_words_set.add(kw)

                if risk_level == "pass":
                    return RiskLevel.Pass, risk_words_set
                elif risk_level == "review":
                    return RiskLevel.Review, risk_words_set
                else:
                    return RiskLevel.Block, risk_words_set

    async def detect_text(self, text: str) -> tuple[RiskLevel, set[str]]:
        """
        对文本进行内容审核，如果文本长度超过10000个字符，则会进行分段审核。

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

            if len(text) <= 10000:
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
    async def detect_image(self, image: str) -> tuple[RiskLevel, set[str]]:  # type: ignore
        """
        对图片进行内容审核。

        Args:
            image (str): 需要审核的图片，可以是base64编码的字符串或URL。

        Returns:
            tuple[RiskLevel, set[str]]: 审核结果，包含风险等级和风险描述集合。

        Raises:
            CensorError: 任何在检测过程中可能抛出的异常。
        """

        if image.startswith("base64://"):
            image_content = image[9:]
            payload = json.dumps({"FileContent": image_content})
        elif image.startswith("http"):
            payload = json.dumps({"FileUrl": image})
        else:
            raise CensorError("预期外的输入")

        headers = self._auth.prepare_request_headers(
            service="ims",
            host="ims.tencentcloudapi.com",
            action="ImageModeration",
            payload=payload,
        )
        async with self._semaphore:
            async with self._session.post(
                self._image_url, headers=headers, data=payload
            ) as response:
                response.raise_for_status()
                result = await response.json()
                res = result["Response"]

                if errmsg := res.get("Error"):
                    raise CensorError(f"内容审核请求异常: {errmsg.get('Message')!s}")

                reason_words_set: set[str] = set()
                risk_level = res.get("Suggestion", "").lower()
                reason_words_set.add(res.get("Label", ""))

                if sl := res.get("SubLabel"):
                    reason_words_set.add(sl)

                if risk_level == "pass":
                    return RiskLevel.Pass, reason_words_set
                elif risk_level == "review":
                    return RiskLevel.Review, reason_words_set
                else:
                    return RiskLevel.Block, reason_words_set
