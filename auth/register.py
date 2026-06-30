"""
用户注册模块
处理新用户注册逻辑，包含密码强度检测
"""

import hashlib
from typing import Dict, Optional

from auth.user_manager import UserManager
from core.password_checker import check_password_strength, PasswordStrength
from logs.logger import log_operation


class Register:
    """用户注册器"""

    def __init__(self):
        self.user_manager = UserManager()

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

    def register(self, username: str, password: str) -> Dict:
        """
        注册新用户

        Args:
            username: 用户名
            password: 密码

        Returns:
            注册结果字典
        """
        # 检查用户名是否为空
        if not username or not username.strip():
            return {'success': False, 'message': '用户名不能为空'}

        username = username.strip()

        # 检查用户名长度
        if len(username) < 3:
            return {'success': False, 'message': '用户名长度至少为3个字符'}

        # 检查用户是否已存在
        if self.user_manager.user_exists(username):
            return {'success': False, 'message': '用户已存在'}

        # 检测密码强度
        strength_result = check_password_strength(password)

        # 弱密码不允许注册
        if strength_result['level'] in (PasswordStrength.VERY_WEAK, PasswordStrength.WEAK):
            return {
                'success': False,
                'message': '密码强度不足',
                'strength': strength_result,
            }

        # 哈希密码并保存
        password_hash = self._hash_password(password)
        self.user_manager.add_user(username, password_hash)

        log_operation('register', f"用户注册成功: {username}",
                      f"密码强度: {strength_result['level']} ({strength_result['score']}分)")

        return {
            'success': True,
            'message': '注册成功',
            'username': username,
            'strength': strength_result,
        }

    def validate_registration(self, username: str, password: str,
                              confirm_password: str) -> Optional[str]:
        """
        验证注册信息

        Args:
            username: 用户名
            password: 密码
            confirm_password: 确认密码

        Returns:
            错误信息，无错误返回 None
        """
        if not username or not username.strip():
            return '用户名不能为空'
        if len(username.strip()) < 3:
            return '用户名长度至少为3个字符'
        if self.user_manager.user_exists(username.strip()):
            return '用户已存在'
        if not password:
            return '密码不能为空'
        if password != confirm_password:
            return '两次输入的密码不一致'
        return None
