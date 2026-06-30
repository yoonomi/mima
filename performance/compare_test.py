"""
AES 与 DES 性能对比测试模块
比较两种算法在不同模式下的性能差异
"""

from typing import List, Dict

from performance.aes_benchmark import run_aes_benchmark, BenchmarkResult
from performance.des_benchmark import run_des_benchmark
from logs.logger import log_operation


def run_compare_test(data: bytes) -> Dict:
    """
    运行 AES 与 DES 性能对比测试

    Args:
        data: 测试数据

    Returns:
        对比测试结果字典
    """
    # 运行 AES 测试（仅测试 CBC 模式，密钥长度 256）
    aes_results = run_aes_benchmark(data, modes=['CBC'], key_sizes=[256])
    # 运行 DES 测试
    des_results = run_des_benchmark(data, modes=['CBC'])

    all_results = aes_results + des_results

    # 计算加速比
    aes_enc_time = aes_results[0].encrypt_time if aes_results else 1
    des_enc_time = des_results[0].encrypt_time if des_results else 1
    speedup_encrypt = des_enc_time / aes_enc_time if aes_enc_time > 0 else 0

    aes_dec_time = aes_results[0].decrypt_time if aes_results else 1
    des_dec_time = des_results[0].decrypt_time if des_results else 1
    speedup_decrypt = des_dec_time / aes_dec_time if aes_dec_time > 0 else 0

    compare_result = {
        'aes_results': [r.__dict__ for r in aes_results],
        'des_results': [r.__dict__ for r in des_results],
        'speedup_encrypt': speedup_encrypt,
        'speedup_decrypt': speedup_decrypt,
        'data_size': len(data),
    }

    log_operation('compare_test', "AES vs DES 性能对比测试完成",
                  f"AES加密速度是DES的 {speedup_encrypt:.2f} 倍, "
                  f"AES解密速度是DES的 {speedup_decrypt:.2f} 倍")

    return compare_result


def get_comparison_summary(results: Dict) -> str:
    """
    生成对比测试摘要

    Args:
        results: 对比测试结果

    Returns:
        摘要字符串
    """
    lines = []
    lines.append("=" * 60)
    lines.append("AES vs DES 性能对比摘要")
    lines.append("=" * 60)
    lines.append(f"测试数据大小: {results['data_size']} 字节")

    for r in results.get('aes_results', []):
        lines.append(f"\nAES-{r['key_size']} ({r['mode']}):")
        lines.append(f"  加密: {r['encrypt_time']*1000:.3f} ms, {r['encrypt_speed']:.2f} MB/s")
        lines.append(f"  解密: {r['decrypt_time']*1000:.3f} ms, {r['decrypt_speed']:.2f} MB/s")

    for r in results.get('des_results', []):
        lines.append(f"\nDES ({r['mode']}):")
        lines.append(f"  加密: {r['encrypt_time']*1000:.3f} ms, {r['encrypt_speed']:.2f} MB/s")
        lines.append(f"  解密: {r['decrypt_time']*1000:.3f} ms, {r['decrypt_speed']:.2f} MB/s")

    lines.append(f"\nAES 加密速度是 DES 的 {results['speedup_encrypt']:.2f} 倍")
    lines.append(f"AES 解密速度是 DES 的 {results['speedup_decrypt']:.2f} 倍")

    return '\n'.join(lines)
