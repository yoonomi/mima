"""
哈希对比模块
比较原文件与解密文件的哈希值，验证解密是否完整
"""

import os
from typing import Dict, Optional

from core.hash_utils import calculate_file_md5, calculate_file_sha1, calculate_file_sha256
from logs.logger import log_operation


def compare_files(original_file: str, decrypted_file: str) -> Dict:
    """
    比较原文件与解密文件的哈希值

    Args:
        original_file: 原始文件路径
        decrypted_file: 解密后文件路径

    Returns:
        比较结果字典
    """
    result = {
        'original_file': original_file,
        'decrypted_file': decrypted_file,
        'algorithms': {},
        'match': False,
    }

    algorithms = {
        'MD5': (calculate_file_md5, calculate_file_md5),
        'SHA1': (calculate_file_sha1, calculate_file_sha1),
        'SHA256': (calculate_file_sha256, calculate_file_sha256),
    }

    all_match = True
    for algo_name, (orig_func, dec_func) in algorithms.items():
        orig_hash = orig_func(original_file)
        dec_hash = dec_func(decrypted_file)

        if orig_hash is None or dec_hash is None:
            match = False
            all_match = False
        else:
            match = orig_hash.lower() == dec_hash.lower()
            if not match:
                all_match = False

        result['algorithms'][algo_name] = {
            'original_hash': orig_hash or 'N/A',
            'decrypted_hash': dec_hash or 'N/A',
            'match': match,
        }

    result['match'] = all_match

    log_operation('hash_compare',
                  f"哈希对比: {'一致' if all_match else '不一致'}",
                  f"原文件: {original_file}, 解密文件: {decrypted_file}")

    return result
