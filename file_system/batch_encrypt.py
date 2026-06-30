"""
批量文件加密模块
支持同时加密多个文件
"""

import os
from typing import List, Optional

from file_system.file_encrypt import encrypt_single_file
from file_system.file_utils import list_files
from logs.logger import log_operation


def batch_encrypt_files(file_list: List[str], algorithm: str = 'AES',
                        mode: str = 'CBC', key: bytes = None,
                        output_dir: str = None, key_size: int = 256) -> List[dict]:
    """
    批量加密多个文件

    Args:
        file_list: 待加密文件路径列表
        algorithm: 加密算法
        mode: 加密模式
        key: 密钥（所有文件使用相同密钥）
        output_dir: 输出目录
        key_size: AES密钥长度

    Returns:
        每个文件的加密结果列表
    """
    results = []
    success_count = 0
    fail_count = 0

    for file_path in file_list:
        try:
            result = encrypt_single_file(file_path, algorithm, mode, key,
                                         output_dir, key_size)
            results.append(result)
            success_count += 1
        except Exception as e:
            results.append({
                'status': 'failed',
                'input_file': file_path,
                'error': str(e),
            })
            fail_count += 1

    log_operation('batch_encrypt',
                  f"批量加密完成: 成功 {success_count}, 失败 {fail_count}",
                  f"算法: {algorithm}, 模式: {mode}")
    return results


def batch_encrypt_directory(directory: str, algorithm: str = 'AES',
                            mode: str = 'CBC', key: bytes = None,
                            extensions: list = None,
                            output_dir: str = None, key_size: int = 256) -> List[dict]:
    """
    加密目录中的所有文件

    Args:
        directory: 目录路径
        algorithm: 加密算法
        mode: 加密模式
        key: 密钥
        extensions: 文件扩展名过滤
        output_dir: 输出目录
        key_size: AES密钥长度

    Returns:
        每个文件的加密结果列表
    """
    files = list_files(directory, extensions)
    if not files:
        log_operation('batch_encrypt_warn', f"目录中没有找到可加密的文件: {directory}")
        return []

    return batch_encrypt_files(files, algorithm, mode, key, output_dir, key_size)
