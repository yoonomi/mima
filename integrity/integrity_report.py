"""
完整性校验报告生成模块
生成文件完整性校验的详细报告
"""

import os
from typing import List, Dict
from datetime import datetime

from integrity.file_hash import compute_file_hashes, save_hash_record
from integrity.hash_compare import compare_files
from logs.logger import log_operation
from config import REPORTS_DIR


def generate_integrity_report(original_file: str, decrypted_file: str,
                              report_file: str = None) -> str:
    """
    生成完整性校验报告

    Args:
        original_file: 原始文件路径
        decrypted_file: 解密后文件路径
        report_file: 报告文件路径

    Returns:
        报告文件路径
    """
    if report_file is None:
        report_file = os.path.join(REPORTS_DIR, 'integrity_report.txt')

    os.makedirs(os.path.dirname(report_file), exist_ok=True)

    # 计算哈希值
    orig_hashes = compute_file_hashes(original_file)
    dec_hashes = compute_file_hashes(decrypted_file)

    # 保存记录
    if orig_hashes:
        save_hash_record(orig_hashes)

    # 比较哈希值
    comparison = compare_files(original_file, decrypted_file)

    # 生成报告
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("         文件完整性校验报告")
    report_lines.append("=" * 60)
    report_lines.append(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    report_lines.append(f"原始文件: {original_file}")
    report_lines.append(f"解密文件: {decrypted_file}")
    report_lines.append("")

    if orig_hashes:
        report_lines.append("-" * 40)
        report_lines.append("【原始文件哈希值】")
        report_lines.append(f"  文件大小: {orig_hashes['file_size_fmt']}")
        report_lines.append(f"  MD5   : {orig_hashes['md5']}")
        report_lines.append(f"  SHA1  : {orig_hashes['sha1']}")
        report_lines.append(f"  SHA256: {orig_hashes['sha256']}")

    report_lines.append("")
    if dec_hashes:
        report_lines.append("-" * 40)
        report_lines.append("【解密文件哈希值】")
        report_lines.append(f"  文件大小: {dec_hashes['file_size_fmt']}")
        report_lines.append(f"  MD5   : {dec_hashes['md5']}")
        report_lines.append(f"  SHA1  : {dec_hashes['sha1']}")
        report_lines.append(f"  SHA256: {dec_hashes['sha256']}")

    report_lines.append("")
    report_lines.append("-" * 40)
    report_lines.append("【哈希对比结果】")
    for algo, data in comparison['algorithms'].items():
        status = "✓ 一致" if data['match'] else "✗ 不一致"
        report_lines.append(f"  {algo}: {status}")

    report_lines.append("")
    report_lines.append("-" * 40)
    if comparison['match']:
        report_lines.append("【结论】文件完整性校验通过 ✓")
        report_lines.append("解密后的文件与原始文件完全一致。")
    else:
        report_lines.append("【结论】文件完整性校验失败 ✗")
        report_lines.append("解密后的文件与原始文件不一致，数据可能已被篡改。")

    report_lines.append("")
    report_lines.append("=" * 60)

    report_content = '\n'.join(report_lines)

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)

    log_operation('integrity_report', f"完整性校验报告已生成: {report_file}",
                  f"校验结果: {'通过' if comparison['match'] else '失败'}")

    return report_file
