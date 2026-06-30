"""
用户信息管理模块
负责用户数据的存储、加载和管理
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime


class UserManager:
    """用户管理器"""

    def __init__(self, users_file: str = None):
        """
        初始化用户管理器

        Args:
            users_file: 用户数据文件路径
        """
        if users_file is None:
            from config import DATABASE_DIR
            users_file = os.path.join(DATABASE_DIR, 'users.json')
        self.users_file = users_file
        self.users = self._load_users()

    def _load_users(self) -> Dict:
        """加载用户数据"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def reload(self):
        """从磁盘重新加载用户数据，确保数据最新"""
        self.users = self._load_users()

    def _save_users(self):
        """保存用户数据"""
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(self.users, f, indent=4, ensure_ascii=False)

    def add_user(self, username: str, password_hash: str) -> bool:
        """
        添加新用户

        Args:
            username: 用户名
            password_hash: 密码哈希值

        Returns:
            是否成功添加
        """
        self.reload()
        if username in self.users:
            return False

        self.users[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_login': None,
        }
        self._save_users()
        return True

    def verify_user(self, username: str, password_hash: str) -> bool:
        """
        验证用户密码

        Args:
            username: 用户名
            password_hash: 密码哈希值

        Returns:
            密码是否正确
        """
        self.reload()
        if username not in self.users:
            return False
        return self.users[username]['password_hash'] == password_hash

    def user_exists(self, username: str) -> bool:
        """检查用户是否存在"""
        self.reload()
        return username in self.users

    def update_last_login(self, username: str):
        """更新最后登录时间"""
        self.reload()
        if username in self.users:
            self.users[username]['last_login'] = datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S')
            self._save_users()

    def get_all_users(self) -> List[str]:
        """获取所有用户名列表"""
        self.reload()
        return list(self.users.keys())

    def get_user_info(self, username: str) -> Optional[Dict]:
        """获取用户信息"""
        self.reload()
        return self.users.get(username)

    def delete_user(self, username: str) -> bool:
        """删除用户"""
        if username in self.users:
            del self.users[username]
            self._save_users()
            return True
        return False

    def change_password(self, username: str, new_password_hash: str) -> bool:
        """修改密码"""
        if username in self.users:
            self.users[username]['password_hash'] = new_password_hash
            self._save_users()
            return True
        return False
