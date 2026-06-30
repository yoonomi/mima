"""
批量文件解密模块
支持同时解密多个文件
"""

import os
from typing import List, Optional

from file_system.file_decrypt import decrypt_single_file
from file_system.file_utils import list_files
from logs.logger import log_operation


def batch_decrypt_files(file_list: List[str], key: bytes, algorithm: str = 'AES',
                        mode: str = 'CBC', output_dir: str = None) -> List[dict]:
    """
    批量解密多个文件

    Args:
        file_list: 待解密文件路径列表
        key: 密钥
        algorithm: 加密算法
        mode: 加密模式
        output_dir: 输出目录

    Returns:
        每个文件的解密结果列表
    """
    results = []
    success_count = 0
    fail_count = 0

    for file_path in file_list:
        try:
            result = decrypt_single_file(file_path, key, algorithm, mode, output_dir)
            results.append(result)
            success_count += 1
        except Exception as e:
            results.append({
                'status': 'failed',
                'input_file': file_path,
                'error': str(e),
            })
            fail_count += 1

    log_operation('batch_decrypt',
                  f"批量解密完成: 成功 {success_count}, 失败 {fail_count}",
                  f"算法: {algorithm}, 模式: {mode}")
    return results


def batch_decrypt_directory(directory: str, key: bytes, algorithm: str = 'AES',
                            mode: str = 'CBC', extensions: list = None,
                            output_dir: str = None) -> List[dict]:
    """
    解密目录中的所有加密文件

    Args:
        directory: 目录路径
        key: 密钥
        algorithm: 加密算法
        mode: 加密模式
        extensions: 文件扩展名过滤
        output_dir: 输出目录

    Returns:
        每个文件的解密结果列表
    """
    files = list_files(directory, extensions)
    if not files:
        log_operation('batch_decrypt_warn', f"目录中没有找到可解密的文件: {directory}")
        return []

    return batch_decrypt_files(files, key, algorithm, mode, output_dir)
