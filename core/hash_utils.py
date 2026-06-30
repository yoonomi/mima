"""
Hash 工具模块
提供 MD5、SHA1、SHA256 等哈希函数用于文件完整性校验
"""

import hashlib
from typing import Optional


def calculate_md5(data: bytes) -> str:
    """
    计算 MD5 哈希值

    Args:
        data: 数据字节串

    Returns:
        MD5 十六进制字符串
    """
    return hashlib.md5(data).hexdigest()


def calculate_sha1(data: bytes) -> str:
    """
    计算 SHA1 哈希值

    Args:
        data: 数据字节串

    Returns:
        SHA1 十六进制字符串
    """
    return hashlib.sha1(data).hexdigest()


def calculate_sha256(data: bytes) -> str:
    """
    计算 SHA256 哈希值

    Args:
        data: 数据字节串

    Returns:
        SHA256 十六进制字符串
    """
    return hashlib.sha256(data).hexdigest()


def calculate_file_md5(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """
    计算文件的 MD5 哈希值

    Args:
        file_path: 文件路径
        chunk_size: 读取块大小

    Returns:
        文件 MD5 十六进制字符串，文件不存在返回 None
    """
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (IOError, FileNotFoundError):
        return None


def calculate_file_sha1(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """
    计算文件的 SHA1 哈希值

    Args:
        file_path: 文件路径
        chunk_size: 读取块大小

    Returns:
        文件 SHA1 十六进制字符串，文件不存在返回 None
    """
    try:
        hash_sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()
    except (IOError, FileNotFoundError):
        return None


def calculate_file_sha256(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """
    计算文件的 SHA256 哈希值

    Args:
        file_path: 文件路径
        chunk_size: 读取块大小

    Returns:
        文件 SHA256 十六进制字符串，文件不存在返回 None
    """
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except (IOError, FileNotFoundError):
        return None


def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """
    验证文件哈希值

    Args:
        file_path: 文件路径
        expected_hash: 期望的哈希值
        algorithm: 哈希算法 (md5, sha1, sha256)

    Returns:
        哈希值是否匹配
    """
    algorithm = algorithm.lower()
    if algorithm == 'md5':
        actual_hash = calculate_file_md5(file_path)
    elif algorithm == 'sha1':
        actual_hash = calculate_file_sha1(file_path)
    elif algorithm == 'sha256':
        actual_hash = calculate_file_sha256(file_path)
    else:
        raise ValueError(f"不支持的哈希算法: {algorithm}")

    if actual_hash is None:
        return False
    return actual_hash.lower() == expected_hash.lower()
