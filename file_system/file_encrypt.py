"""
单文件加密模块
使用 AES 或 DES 算法对单个文件进行加密
"""

import os
from typing import Optional

from core.aes_crypto import encrypt_file as aes_encrypt_file, generate_key as aes_gen_key
from core.des_crypto import encrypt_file as des_encrypt_file, generate_key as des_gen_key
from file_system.file_utils import get_file_size, format_file_size, ensure_directory
from logs.logger import log_operation
from config import ENCRYPTED_DIR


def encrypt_single_file(input_file: str, algorithm: str = 'AES',
                        mode: str = 'CBC', key: bytes = None,
                        output_dir: str = None, key_size: int = 256) -> dict:
    """
    加密单个文件

    Args:
        input_file: 输入文件路径
        algorithm: 加密算法 (AES/DES)
        mode: 加密模式
        key: 密钥，不提供则自动生成
        output_dir: 输出目录
        key_size: AES密钥长度

    Returns:
        加密结果信息字典
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"文件不存在: {input_file}")

    if output_dir is None:
        output_dir = ENCRYPTED_DIR
    ensure_directory(output_dir)

    # 获取文件信息
    original_size = get_file_size(input_file) or 0
    basename = os.path.basename(input_file)
    name_no_ext, ext = os.path.splitext(basename)
    # 文件名包含算法和模式，避免不同加密方式覆盖
    output_file = os.path.join(output_dir, f"{name_no_ext}_{algorithm}_{mode}_encrypted{ext}")

    try:
        if algorithm.upper() == 'AES':
            if key is None:
                key = aes_gen_key(key_size)
            result = aes_encrypt_file(input_file, output_file, key, mode)
        elif algorithm.upper() == 'DES':
            if key is None:
                key = des_gen_key()
            result = des_encrypt_file(input_file, output_file, key, mode)
        else:
            raise ValueError(f"不支持的算法: {algorithm}，可选 AES/DES")

        encrypted_size = get_file_size(output_file) or 0

        encrypt_result = {
            'status': 'success',
            'algorithm': algorithm.upper(),
            'mode': mode,
            'input_file': input_file,
            'output_file': output_file,
            'original_size': original_size,
            'original_size_fmt': format_file_size(original_size),
            'encrypted_size': encrypted_size,
            'encrypted_size_fmt': format_file_size(encrypted_size),
            'key': key,
        }

        log_operation('encrypt', f"文件加密成功: {input_file} -> {output_file}",
                      f"算法: {algorithm}, 模式: {mode}, 原大小: {format_file_size(original_size)}")
        return encrypt_result

    except Exception as e:
        log_operation('encrypt_error', f"文件加密失败: {input_file}", str(e))
        raise


def encrypt_with_key(input_file: str, key: bytes, algorithm: str = 'AES',
                     mode: str = 'CBC', output_dir: str = None) -> dict:
    """
    使用指定密钥加密文件

    Args:
        input_file: 输入文件路径
        key: 密钥
        algorithm: 加密算法
        mode: 加密模式
        output_dir: 输出目录

    Returns:
        加密结果信息字典
    """
    return encrypt_single_file(input_file, algorithm, mode, key, output_dir)
