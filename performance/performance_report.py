"""
性能测试报告生成模块
生成 AES 与 DES 加密性能测试的详细报告
"""

import os
import json
from typing import List, Dict
from datetime import datetime

from performance.aes_benchmark import BenchmarkResult, run_aes_benchmark
from performance.des_benchmark import run_des_benchmark
from performance.compare_test import run_compare_test
from logs.logger import log_operation
from config import REPORTS_DIR, DATABASE_DIR


def generate_performance_report(data: bytes, report_file: str = None) -> str:
    """
    生成性能测试报告

    Args:
        data: 测试数据
        report_file: 报告文件路径

    Returns:
        报告文件路径
    """
    if report_file is None:
        report_file = os.path.join(REPORTS_DIR, 'performance_report.txt')

    os.makedirs(os.path.dirname(report_file), exist_ok=True)

    # 运行所有测试
    aes_results = run_aes_benchmark(data)
    des_results = run_des_benchmark(data)
    compare_results = run_compare_test(data)

    # 保存测试记录
    save_performance_records(aes_results, des_results, compare_results)

    # 生成报告
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("              加密性能测试报告")
    report_lines.append("=" * 70)
    report_lines.append(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"测试数据大小: {len(data)} 字节 ({len(data) / 1024:.2f} KB)")
    report_lines.append("")

    # AES 测试结果
    report_lines.append("=" * 70)
    report_lines.append("一、AES 加密/解密性能测试")
    report_lines.append("-" * 70)
    report_lines.append(f"{'模式':<8} {'密钥长度':<10} {'加密耗时(ms)':<15} {'解密耗时(ms)':<15} "
                        f"{'加密速度(MB/s)':<15} {'解密速度(MB/s)':<15}")
    report_lines.append("-" * 70)

    for r in aes_results:
        report_lines.append(
            f"{r.mode:<8} {r.key_size:<10} {r.encrypt_time*1000:<15.3f} "
            f"{r.decrypt_time*1000:<15.3f} {r.encrypt_speed:<15.2f} {r.decrypt_speed:<15.2f}"
        )

    # DES 测试结果
    report_lines.append("")
    report_lines.append("=" * 70)
    report_lines.append("二、DES 加密/解密性能测试")
    report_lines.append("-" * 70)
    report_lines.append(f"{'模式':<8} {'密钥长度':<10} {'加密耗时(ms)':<15} {'解密耗时(ms)':<15} "
                        f"{'加密速度(MB/s)':<15} {'解密速度(MB/s)':<15}")
    report_lines.append("-" * 70)

    for r in des_results:
        report_lines.append(
            f"{r.mode:<8} {r.key_size:<10} {r.encrypt_time*1000:<15.3f} "
            f"{r.decrypt_time*1000:<15.3f} {r.encrypt_speed:<15.2f} {r.decrypt_speed:<15.2f}"
        )

    # 对比分析
    report_lines.append("")
    report_lines.append("=" * 70)
    report_lines.append("三、AES vs DES 性能对比分析")
    report_lines.append("-" * 70)

    if compare_results['aes_results'] and compare_results['des_results']:
        aes_cbc = compare_results['aes_results'][0]
        des_cbc = compare_results['des_results'][0]

        report_lines.append(f"AES-256 CBC 加密耗时: {aes_cbc['encrypt_time']*1000:.3f} ms")
        report_lines.append(f"DES CBC 加密耗时:     {des_cbc['encrypt_time']*1000:.3f} ms")
        report_lines.append(f"AES 加密速度是 DES 的 {compare_results['speedup_encrypt']:.2f} 倍")
        report_lines.append("")
        report_lines.append(f"AES-256 CBC 解密耗时: {aes_cbc['decrypt_time']*1000:.3f} ms")
        report_lines.append(f"DES CBC 解密耗时:     {des_cbc['decrypt_time']*1000:.3f} ms")
        report_lines.append(f"AES 解密速度是 DES 的 {compare_results['speedup_decrypt']:.2f} 倍")

    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("【结论】")
    report_lines.append("1. AES 算法在安全性和性能上均优于 DES 算法。")
    report_lines.append("2. AES 支持更多的工作模式（ECB、CBC、CFB、OFB、CTR）。")
    report_lines.append("3. AES 支持更长的密钥（128、192、256位），安全性更高。")
    report_lines.append("4. DES 的 56 位密钥在现代计算能力下已不安全，易受暴力破解攻击。")
    report_lines.append("5. 推荐在实际应用中使用 AES-256 加密算法。")
    report_lines.append("")
    report_lines.append("=" * 70)

    report_content = '\n'.join(report_lines)

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)

    log_operation('performance_report', f"性能测试报告已生成: {report_file}")

    return report_file


def save_performance_records(aes_results: List[BenchmarkResult],
                             des_results: List[BenchmarkResult],
                             compare_results: Dict):
    """保存性能测试记录"""
    records_file = os.path.join(DATABASE_DIR, 'performance_records.json')

    records = []
    if os.path.exists(records_file):
        try:
            with open(records_file, 'r', encoding='utf-8') as f:
                records = json.load(f)
        except (json.JSONDecodeError, IOError):
            records = []

    record = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'data_size': compare_results.get('data_size', 0),
        'aes_results': [r.__dict__ for r in aes_results],
        'des_results': [r.__dict__ for r in des_results],
        'speedup_encrypt': compare_results.get('speedup_encrypt', 0),
        'speedup_decrypt': compare_results.get('speedup_decrypt', 0),
    }

    records.append(record)

    os.makedirs(os.path.dirname(records_file), exist_ok=True)
    with open(records_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=4, ensure_ascii=False)
