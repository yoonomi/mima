"""
AES 加密/解密性能测试模块
测试不同模式、不同密钥长度下的加解密耗时
"""

import time
import os
from typing import Dict, List
from dataclasses import dataclass

from core.aes_crypto import encrypt, decrypt, generate_key, AES_MODES


@dataclass
class BenchmarkResult:
    """性能测试结果"""
    algorithm: str
    mode: str
    key_size: int
    data_size: int
    encrypt_time: float
    decrypt_time: float
    encrypt_speed: float  # MB/s
    decrypt_speed: float  # MB/s


def run_aes_benchmark(data: bytes, modes: list = None,
                      key_sizes: list = None) -> List[BenchmarkResult]:
    """
    运行 AES 性能测试

    Args:
        data: 测试数据
        modes: 待测试的加密模式列表
        key_sizes: 待测试的密钥长度列表

    Returns:
        测试结果列表
    """
    if modes is None:
        modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    if key_sizes is None:
        key_sizes = [128, 192, 256]

    results = []
    data_size = len(data)

    for key_size in key_sizes:
        key = generate_key(key_size)
        for mode in modes:
            if mode not in AES_MODES:
                continue

            # 加密测试
            encrypt_times = []
            decrypt_times = []

            # 运行多次取平均
            runs = 5 if data_size > 1024 * 1024 else 10

            for _ in range(runs):
                # 加密测试
                start = time.perf_counter()
                enc_result = encrypt(data, key, mode)
                encrypt_time = time.perf_counter() - start
                encrypt_times.append(encrypt_time)

                # 解密测试
                start = time.perf_counter()
                decrypt(enc_result['ciphertext'], key, mode, enc_result['iv'])
                decrypt_time = time.perf_counter() - start
                decrypt_times.append(decrypt_time)

            avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
            avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)

            # 计算速度 (MB/s)
            encrypt_speed = (data_size / (1024 * 1024)) / avg_encrypt_time if avg_encrypt_time > 0 else 0
            decrypt_speed = (data_size / (1024 * 1024)) / avg_decrypt_time if avg_decrypt_time > 0 else 0

            results.append(BenchmarkResult(
                algorithm='AES',
                mode=mode,
                key_size=key_size,
                data_size=data_size,
                encrypt_time=avg_encrypt_time,
                decrypt_time=avg_decrypt_time,
                encrypt_speed=encrypt_speed,
                decrypt_speed=decrypt_speed,
            ))

    return results
