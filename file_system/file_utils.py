"""
文件工具函数模块
提供文件路径、大小、类型等工具函数
"""

import os
from typing import Optional, Tuple


# 常见文件类型的 magic bytes 映射
FILE_TYPE_MAGIC = {
    'jpg': (b'\xff\xd8\xff', 'JPEG图像'),
    'png': (b'\x89PNG\r\n\x1a\n', 'PNG图像'),
    'gif': (b'GIF8', 'GIF图像'),
    'pdf': (b'%PDF', 'PDF文档'),
    'doc': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'Word文档(旧)'),
    'docx': (b'PK\x03\x04', 'Word文档'),
    'zip': (b'PK\x03\x04', 'ZIP压缩文件'),
    'rar': (b'Rar!\x1a\x07', 'RAR压缩文件'),
    'txt': (None, '文本文件'),
}


def get_file_size(file_path: str) -> Optional[int]:
    """
    获取文件大小（字节）

    Args:
        file_path: 文件路径

    Returns:
        文件字节数，文件不存在返回 None
    """
    try:
        return os.path.getsize(file_path)
    except (OSError, FileNotFoundError):
        return None


def format_file_size(size_bytes: int) -> str:
    """
    格式化文件大小为可读字符串

    Args:
        size_bytes: 文件字节数

    Returns:
        格式化后的大小字符串，如 "1.23 MB"
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_file_extension(file_path: str) -> str:
    """
    获取文件扩展名

    Args:
        file_path: 文件路径

    Returns:
        文件扩展名（小写，不含点号）
    """
    _, ext = os.path.splitext(file_path)
    return ext.lower().lstrip('.')


def get_file_type(file_path: str) -> str:
    """
    检测文件类型

    Args:
        file_path: 文件路径

    Returns:
        文件类型描述
    """
    ext = get_file_extension(file_path)
    if ext in ('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar'):
        return FILE_TYPE_MAGIC.get(ext, ('', f'.{ext}文件'))[1]
    return f'.{ext}文件'


def is_binary_file(file_path: str, sample_size: int = 8192) -> bool:
    """
    检测文件是否为二进制文件

    Args:
        file_path: 文件路径
        sample_size: 采样字节数

    Returns:
        是否为二进制文件
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
        # 检查是否有空字节
        return b'\x00' in sample
    except IOError:
        return True


def list_files(directory: str, extensions: list = None) -> list:
    """
    列出目录中的文件

    Args:
        directory: 目录路径
        extensions: 文件扩展名过滤列表，如 ['.txt', '.docx']

    Returns:
        文件路径列表
    """
    if not os.path.exists(directory):
        return []

    files = []
    for f in os.listdir(directory):
        file_path = os.path.join(directory, f)
        if os.path.isfile(file_path):
            if extensions:
                _, ext = os.path.splitext(f)
                if ext.lower() in extensions:
                    files.append(file_path)
            else:
                files.append(file_path)
    return files


def ensure_directory(directory: str) -> bool:
    """
    确保目录存在，不存在则创建

    Args:
        directory: 目录路径

    Returns:
        目录是否就绪
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except OSError:
        return False


def get_output_path(input_path: str, output_dir: str, prefix: str = '') -> str:
    """
    生成输出文件路径

    Args:
        input_path: 输入文件路径
        output_dir: 输出目录
        prefix: 文件名前缀

    Returns:
        输出文件完整路径
    """
    basename = os.path.basename(input_path)
    if prefix:
        basename = f"{prefix}_{basename}"
    return os.path.join(output_dir, basename)
