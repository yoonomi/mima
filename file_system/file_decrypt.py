"""
单文件解密模块
使用 AES 或 DES 算法对单个文件进行解密
"""

import os
from typing import Optional

from core.aes_crypto import decrypt_file as aes_decrypt_file
from core.des_crypto import decrypt_file as des_decrypt_file
from file_system.file_utils import get_file_size, format_file_size, ensure_directory
from logs.logger import log_operation
from config import DECRYPTED_DIR


def decrypt_single_file(input_file: str, key: bytes, algorithm: str = 'AES',
                        mode: str = 'CBC', output_dir: str = None) -> dict:
    """
    解密单个文件

    Args:
        input_file: 输入文件（密文）路径
        key: 密钥
        algorithm: 加密算法 (AES/DES)
        mode: 加密模式
        output_dir: 输出目录

    Returns:
        解密结果信息字典
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"文件不存在: {input_file}")

    if output_dir is None:
        output_dir = DECRYPTED_DIR
    ensure_directory(output_dir)

    # 获取文件信息
    encrypted_size = get_file_size(input_file) or 0
    basename = os.path.basename(input_file)
    name_no_ext, ext = os.path.splitext(basename)
    # 移除可能有的 _encrypted 后缀
    name_no_ext = name_no_ext.replace('_encrypted', '').replace('_decrypted', '')
    output_file = os.path.join(output_dir, f"{name_no_ext}_decrypted{ext}")

    try:
        if algorithm.upper() == 'AES':
            aes_decrypt_file(input_file, output_file, key, mode)
        elif algorithm.upper() == 'DES':
            des_decrypt_file(input_file, output_file, key, mode)
        else:
            raise ValueError(f"不支持的算法: {algorithm}，可选 AES/DES")

        decrypted_size = get_file_size(output_file) or 0

        decrypt_result = {
            'status': 'success',
            'algorithm': algorithm.upper(),
            'mode': mode,
            'input_file': input_file,
            'output_file': output_file,
            'encrypted_size': encrypted_size,
            'encrypted_size_fmt': format_file_size(encrypted_size),
            'decrypted_size': decrypted_size,
            'decrypted_size_fmt': format_file_size(decrypted_size),
        }

        log_operation('decrypt', f"文件解密成功: {input_file} -> {output_file}",
                      f"算法: {algorithm}, 模式: {mode}")
        return decrypt_result

    except Exception as e:
        log_operation('decrypt_error', f"文件解密失败: {input_file}", str(e))
        raise
