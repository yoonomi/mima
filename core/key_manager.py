"""
密钥生成与管理模块
支持 AES 和 DES 密钥的生成、保存、加载和管理
"""

import os
import json
import base64
from typing import Optional, Dict
from Crypto.Random import get_random_bytes

from config import DATABASE_DIR


class KeyManager:
    """密钥管理器"""

    def __init__(self, keys_file: str = None):
        """
        初始化密钥管理器

        Args:
            keys_file: 密钥数据库文件路径
        """
        if keys_file is None:
            keys_file = os.path.join(DATABASE_DIR, 'keys.json')
        self.keys_file = keys_file
        self.keys = self._load_keys()

    def _load_keys(self) -> Dict:
        """加载密钥数据库"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def reload(self):
        """从磁盘重新加载密钥数据"""
        self.keys = self._load_keys()

    def _save_keys(self):
        """保存密钥数据库"""
        os.makedirs(os.path.dirname(self.keys_file), exist_ok=True)
        with open(self.keys_file, 'w', encoding='utf-8') as f:
            json.dump(self.keys, f, indent=4, ensure_ascii=False)

    def generate_aes_key(self, key_size: int = 256, key_name: str = None) -> Dict:
        """
        生成 AES 密钥并保存

        Args:
            key_size: 密钥长度 (128, 192, 256)
            key_name: 密钥名称

        Returns:
            密钥信息
        """
        self.reload()
        if key_size not in (128, 192, 256):
            raise ValueError(f"不支持的密钥长度: {key_size}")

        key_bytes = get_random_bytes(key_size // 8)
        key_b64 = base64.b64encode(key_bytes).decode('utf-8')

        if key_name is None:
            key_name = f"AES_KEY_{key_size}_{len(self.keys) + 1}"

        key_info = {
            'name': key_name,
            'algorithm': 'AES',
            'key_size': key_size,
            'key_b64': key_b64,
            'created': self._get_timestamp(),
        }

        self.keys[key_name] = key_info
        self._save_keys()
        return key_info

    def generate_des_key(self, key_name: str = None) -> Dict:
        """
        生成 DES 密钥并保存

        Args:
            key_name: 密钥名称

        Returns:
            密钥信息
        """
        self.reload()
        key_bytes = get_random_bytes(8)
        key_b64 = base64.b64encode(key_bytes).decode('utf-8')

        if key_name is None:
            key_name = f"DES_KEY_{len(self.keys) + 1}"

        key_info = {
            'name': key_name,
            'algorithm': 'DES',
            'key_size': 56,
            'key_b64': key_b64,
            'created': self._get_timestamp(),
        }

        self.keys[key_name] = key_info
        self._save_keys()
        return key_info

    def get_key(self, key_name: str) -> Optional[bytes]:
        """
        获取密钥字节数据

        Args:
            key_name: 密钥名称

        Returns:
            密钥字节串，不存在返回 None
        """
        self.reload()
        if key_name not in self.keys:
            return None
        try:
            return base64.b64decode(self.keys[key_name]['key_b64'])
        except Exception:
            return None

    def get_key_info(self, key_name: str) -> Optional[Dict]:
        """获取密钥信息"""
        self.reload()
        return self.keys.get(key_name)

    def list_keys(self) -> Dict:
        """列出所有密钥"""
        self.reload()
        return self.keys

    def delete_key(self, key_name: str) -> bool:
        """
        删除密钥

        Args:
            key_name: 密钥名称

        Returns:
            是否成功删除
        """
        self.reload()
        if key_name in self.keys:
            del self.keys[key_name]
            self._save_keys()
            return True
        return False

    def import_key(self, key_b64: str, key_name: str, algorithm: str = 'AES',
                   key_size: int = 256) -> Dict:
        """
        导入密钥

        Args:
            key_b64: Base64 编码的密钥
            key_name: 密钥名称
            algorithm: 算法类型
            key_size: 密钥长度

        Returns:
            密钥信息
        """
        self.reload()
        key_info = {
            'name': key_name,
            'algorithm': algorithm,
            'key_size': key_size,
            'key_b64': key_b64,
            'created': self._get_timestamp(),
            'imported': True,
        }
        self.keys[key_name] = key_info
        self._save_keys()
        return key_info

    def export_key(self, key_name: str) -> Optional[str]:
        """
        导出密钥（Base64 格式）

        Args:
            key_name: 密钥名称

        Returns:
            Base64 编码的密钥字符串
        """
        self.reload()
        if key_name in self.keys:
            return self.keys[key_name]['key_b64']
        return None

    @staticmethod
    def _get_timestamp() -> str:
        """获取当前时间戳字符串"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
