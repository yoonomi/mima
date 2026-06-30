"""
文件哈希计算模块
计算文件的 MD5、SHA1、SHA256 哈希值
"""

import os
import json
from typing import Dict, Optional
from datetime import datetime

from core.hash_utils import calculate_file_md5, calculate_file_sha1, calculate_file_sha256
from file_system.file_utils import get_file_size, format_file_size
from config import DATABASE_DIR


def compute_file_hashes(file_path: str) -> Optional[Dict]:
    """
    计算文件的所有哈希值

    Args:
        file_path: 文件路径

    Returns:
        包含所有哈希值的字典
    """
    if not os.path.exists(file_path):
        return None

    return {
        'file_path': file_path,
        'file_name': os.path.basename(file_path),
        'file_size': get_file_size(file_path),
        'file_size_fmt': format_file_size(get_file_size(file_path) or 0),
        'md5': calculate_file_md5(file_path) or '',
        'sha1': calculate_file_sha1(file_path) or '',
        'sha256': calculate_file_sha256(file_path) or '',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


def save_hash_record(record: Dict, records_file: str = None):
    """
    保存哈希记录

    Args:
        record: 哈希记录字典
        records_file: 记录文件路径
    """
    if records_file is None:
        records_file = os.path.join(DATABASE_DIR, 'hash_records.json')

    records = []
    if os.path.exists(records_file):
        try:
            with open(records_file, 'r', encoding='utf-8') as f:
                records = json.load(f)
        except (json.JSONDecodeError, IOError):
            records = []

    records.append(record)

    os.makedirs(os.path.dirname(records_file), exist_ok=True)
    with open(records_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=4, ensure_ascii=False)


def get_hash_records(records_file: str = None) -> list:
    """
    获取哈希记录列表

    Args:
        records_file: 记录文件路径

    Returns:
        哈希记录列表
    """
    if records_file is None:
        records_file = os.path.join(DATABASE_DIR, 'hash_records.json')

    if os.path.exists(records_file):
        try:
            with open(records_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []
