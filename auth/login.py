"""
用户登录模块
处理用户登录验证逻辑
"""

import hashlib
from typing import Dict, Optional

from auth.user_manager import UserManager
from logs.logger import log_operation


class Login:
    """用户登录器"""

    def __init__(self):
        self.user_manager = UserManager()
        self.current_user: Optional[str] = None

    @staticmethod
    def _hash_password(password: str) -> str:
        """
        对密码进行 SHA256 哈希

        Args:
            password: 明文密码

        Returns:
            哈希后的十六进制字符串
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def login(self, username: str, password: str) -> Dict:
        """
        用户登录

        Args:
            username: 用户名
            password: 密码

        Returns:
            登录结果字典
        """
        username = username.strip()

        if not username:
            return {'success': False, 'message': '请输入用户名'}

        if not password:
            return {'success': False, 'message': '请输入密码'}

        if not self.user_manager.user_exists(username):
            return {'success': False, 'message': '用户名或密码错误'}

        password_hash = self._hash_password(password)
        if self.user_manager.verify_user(username, password_hash):
            self.current_user = username
            self.user_manager.update_last_login(username)
            log_operation('login', f"用户登录成功: {username}")
            return {'success': True, 'message': '登录成功', 'username': username}
        else:
            log_operation('login_failed', f"用户登录失败: {username}")
            return {'success': False, 'message': '用户名或密码错误'}

    def logout(self):
        """用户登出"""
        if self.current_user:
            log_operation('logout', f"用户登出: {self.current_user}")
            self.current_user = None

    def is_logged_in(self) -> bool:
        """检查是否有用户已登录"""
        return self.current_user is not None

    def get_current_user(self) -> Optional[str]:
        """获取当前登录用户名"""
        return self.current_user
