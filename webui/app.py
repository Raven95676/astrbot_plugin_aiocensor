import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

import jwt
from quart import Quart, Response, jsonify, request, send_from_directory

from ..db import DBManager  # type:ignore

logger = logging.getLogger(__name__)


def create_app(config: dict[str, str], db_mgr: DBManager) -> Quart:
    """创建并配置Quart应用实例

    Args:
        config: 应用配置字典
        db_mgr: 数据库管理器实例

    Returns:
        配置好的Quart应用实例
    """
    app = Quart(__name__, static_folder="dist", static_url_path="")

    SECRET_KEY = config.get("secret_key", "default_secret_key")

    async def format_response(
        data: dict[str, Any] | None = None, message: str = "", status_code: int = 200
    ) -> tuple[Response, int]:
        """格式化API响应

        Args:
            data: 响应数据
            message: 响应消息
            status_code: HTTP状态码

        Returns:
            格式化的JSON响应和状态码
        """
        response = {"success": status_code < 400, "message": message}
        if data is not None:
            response.update(data)
        return jsonify(response), status_code

    def generate_tokens() -> tuple[str, str]:
        """生成JWT访问令牌和刷新令牌

        Returns:
            访问令牌和刷新令牌
        """
        access_token = jwt.encode(
            {
                "role": "admin",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            },
            SECRET_KEY,
            algorithm="HS256",
        )
        refresh_token = jwt.encode(
            {"role": "admin", "exp": datetime.now(timezone.utc) + timedelta(days=30)},
            SECRET_KEY,
            algorithm="HS256",
        )
        return access_token, refresh_token

    def verify_token(token: str) -> dict[str, Any] | None:
        """验证JWT令牌

        Args:
            token: JWT令牌字符串

        Returns:
            解码后的令牌载荷，如果令牌无效则返回None
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            logger.warning("Token verification failed: invalid token")
            return None

    def clean_input(text: str) -> str:
        """预处理输入文本，去除空格

        Args:
            text: 输入文本

        Returns:
            处理后的文本
        """
        if text:
            return text.strip()
        return ""

    def token_required(func):
        """验证请求中的令牌的装饰器"""

        @wraps(func)
        async def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                logger.warning("Missing or invalid authorization header")
                return await format_response(
                    message="缺少或无效的令牌", status_code=401
                )

            token = auth_header.split(" ")[1].strip()
            payload = verify_token(token)
            if not payload:
                return await format_response(
                    message="令牌无效或已过期", status_code=401
                )

            request.auth = payload
            return await func(*args, **kwargs)

        return decorated

    @app.route("/api/login", methods=["POST"])
    async def login() -> tuple[Response, int]:
        """处理用户登录并发放令牌"""
        try:
            data = await request.get_json()
            if not data:
                return await format_response(message="无效的请求数据", status_code=400)

            password = data.get("password", "")
            password = clean_input(password)

            if not password:
                return await format_response(message="缺少密码", status_code=400)

            expected_password = config.get("password", "default")
            if password != expected_password:
                logger.warning("Invalid login attempt with incorrect password")
                return await format_response(message="密码错误", status_code=401)

            access_token, refresh_token = generate_tokens()
            return await format_response(
                data={"access_token": access_token, "refresh_token": refresh_token},
                message="登录成功",
            )
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            return await format_response(message="登录失败", status_code=500)

    @app.route("/api/refresh", methods=["POST"])
    async def refresh() -> tuple[Response, int]:
        """使用刷新令牌获取新的访问令牌"""
        try:
            data = await request.get_json()
            if not data:
                return await format_response(message="无效的请求数据", status_code=400)

            refresh_token = data.get("refresh_token", "")
            refresh_token = clean_input(refresh_token)

            if not refresh_token:
                return await format_response(message="缺少刷新令牌", status_code=400)

            payload = verify_token(refresh_token)
            if not payload:
                logger.warning("Invalid refresh token provided")
                return await format_response(message="无效的刷新令牌", status_code=401)

            access_token, new_refresh_token = generate_tokens()
            return await format_response(
                data={"access_token": access_token, "refresh_token": new_refresh_token},
                message="刷新成功",
            )
        except Exception as e:
            logger.error(f"Refresh error: {str(e)}", exc_info=True)
            return await format_response(message="刷新令牌失败", status_code=500)

    @app.route("/api/audit-logs/<string:log_id>/dispose", methods=["POST"])
    @token_required
    async def dispose_log(log_id: str) -> tuple[Response, int]:
        """处理审计日志的处置操作"""
        try:
            log_id = clean_input(log_id)
            data = await request.get_json()
            if not data:
                return await format_response(message="无效的请求数据", status_code=400)

            actions = data.get("actions", [])
            return await format_response(
                message=f"此功能暂未实现{actions}", status_code=501
            )
        except Exception as e:
            logger.error(f"Error disposing log {log_id}: {str(e)}", exc_info=True)
            return await format_response(message="处置失败", status_code=500)

    @app.route("/api/audit-logs/<string:log_id>/ignore", methods=["POST"])
    @token_required
    async def ignore_log(log_id: str) -> tuple[Response, int]:
        """忽略（删除）审计日志"""
        try:
            log_id = clean_input(log_id)
            async with db_mgr:
                if not await db_mgr.delete_audit_log(log_id):
                    logger.warning(f"Log not found: {log_id}")
                    return await format_response(message="日志不存在", status_code=404)
                return await format_response(
                    message="已删除日志", data={"log_id": log_id}
                )
        except Exception as e:
            logger.error(f"Error deleting log {log_id}: {str(e)}", exc_info=True)
            return await format_response(message="删除日志失败", status_code=500)

    @app.route("/api/blacklist", methods=["POST"])
    @token_required
    async def add_to_blacklist() -> tuple[Response, int]:
        """添加条目到黑名单"""
        try:
            data = await request.get_json()
            if not data:
                return await format_response(message="无效的请求数据", status_code=400)

            user_id = data.get("userId", "")
            reason = data.get("reason", "")

            user_id = clean_input(user_id)
            reason = clean_input(reason)

            if not user_id or not reason:
                logger.warning("Missing required parameters for blacklist addition")
                return await format_response(message="缺少必要参数", status_code=400)

            async with db_mgr:
                existing = await db_mgr.search_blacklist(user_id)
                if any(entry.identifier == user_id for entry in existing):
                    return await format_response(
                        message="用户已在黑名单中", status_code=409
                    )

                record_id = await db_mgr.add_blacklist_entry(user_id, reason)
                return await format_response(
                    data={"id": record_id, "user": user_id, "reason": reason},
                    message="已添加至黑名单",
                    status_code=201,
                )
        except Exception as e:
            logger.error(f"Error adding to blacklist: {str(e)}", exc_info=True)
            return await format_response(message="添加黑名单失败", status_code=500)

    @app.route("/api/blacklist/<string:record_id>", methods=["DELETE"])
    @token_required
    async def delete_blacklist(record_id: str) -> tuple[Response, int]:
        """从黑名单中删除条目"""
        try:
            record_id = clean_input(record_id)
            async with db_mgr:
                if not await db_mgr.delete_blacklist_entry(record_id):
                    logger.warning(f"Blacklist record not found: {record_id}")
                    return await format_response(
                        message="黑名单记录不存在", status_code=404
                    )
                return await format_response(
                    data={"record_id": record_id}, message="已移出黑名单"
                )
        except Exception as e:
            logger.error(f"Error removing from blacklist: {str(e)}", exc_info=True)
            return await format_response(message="移除黑名单失败", status_code=500)

    @app.route("/api/sensitive-words", methods=["POST"])
    @token_required
    async def add_sensitive_word() -> tuple[Response, int]:
        """添加敏感词"""
        try:
            data = await request.get_json()
            if not data:
                return await format_response(message="无效的请求数据", status_code=400)

            word = data.get("word", "")
            word = clean_input(word)

            if not word:
                logger.warning("Missing sensitive word content")
                return await format_response(message="缺少敏感词内容", status_code=400)

            async with db_mgr:
                existing = await db_mgr.search_sensitive_words(word)
                if any(entry.word == word for entry in existing):
                    return await format_response(
                        message="敏感词已存在", status_code=409
                    )

                word_id = await db_mgr.add_sensitive_word(word)
                return await format_response(
                    data={"id": word_id, "word": word},
                    message="敏感词添加成功",
                    status_code=201,
                )
        except Exception as e:
            logger.error(f"Error adding sensitive word: {str(e)}", exc_info=True)
            return await format_response(message="添加敏感词失败", status_code=500)

    @app.route("/api/sensitive-words/<string:word_id>", methods=["DELETE"])
    @token_required
    async def delete_sensitive_word(word_id: str) -> tuple[Response, int]:
        """删除敏感词"""
        try:
            word_id = clean_input(word_id)
            async with db_mgr:
                if not await db_mgr.delete_sensitive_word(word_id):
                    logger.warning(f"Sensitive word not found: {word_id}")
                    return await format_response(
                        message="敏感词不存在", status_code=404
                    )
                return await format_response(
                    data={"word_id": word_id}, message="敏感词删除成功"
                )
        except Exception as e:
            logger.error(f"Error deleting sensitive word: {str(e)}", exc_info=True)
            return await format_response(message="删除敏感词失败", status_code=500)

    @app.route("/", strict_slashes=False)
    async def serve_root():
        """提供前端静态文件"""
        return await send_from_directory(app.static_folder, "index.html")

    return app
