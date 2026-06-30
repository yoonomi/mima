"""
DES 加密/解密性能测试模块
测试不同模式下 DES 的加解密耗时
"""

import time
from typing import List

from core.des_crypto import encrypt, decrypt, generate_key, DES_MODES
from performance.aes_benchmark import BenchmarkResult


def run_des_benchmark(data: bytes, modes: list = None) -> List[BenchmarkResult]:
    """
    运行 DES 性能测试

    Args:
        data: 测试数据
        modes: 待测试的加密模式

    Returns:
        测试结果列表
    """
    if modes is None:
        modes = ['ECB', 'CBC']

    results = []
    data_size = len(data)
    key = generate_key()

    for mode in modes:
        if mode not in DES_MODES:
            continue

        encrypt_times = []
        decrypt_times = []

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

        encrypt_speed = (data_size / (1024 * 1024)) / avg_encrypt_time if avg_encrypt_time > 0 else 0
        decrypt_speed = (data_size / (1024 * 1024)) / avg_decrypt_time if avg_decrypt_time > 0 else 0

        results.append(BenchmarkResult(
            algorithm='DES',
            mode=mode,
            key_size=56,
            data_size=data_size,
            encrypt_time=avg_encrypt_time,
            decrypt_time=avg_decrypt_time,
            encrypt_speed=encrypt_speed,
            decrypt_speed=decrypt_speed,
        ))

    return results
