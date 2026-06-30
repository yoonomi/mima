"""
Secure_AES_System - 基于对称密码体系的数据加密解密系统
主程序入口，提供命令行交互菜单

作者: 2023337621104 金科丞
日期: 2026-06-30
"""

import os
import sys

# 确保项目根目录在系统路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ROOT_DIR, TEST_DATA_DIR, ENCRYPTED_DIR, DECRYPTED_DIR,
    REPORTS_DIR,
)
from logs.logger import log_operation, get_recent_logs
from core.key_manager import KeyManager
from core.password_checker import check_password_strength, generate_strong_password
from core.aes_crypto import get_supported_modes as aes_supported_modes
from core.des_crypto import get_supported_modes as des_supported_modes
from auth.login import Login
from auth.register import Register
from file_system.file_encrypt import encrypt_single_file
from file_system.file_decrypt import decrypt_single_file
from file_system.batch_encrypt import batch_encrypt_files
from file_system.batch_decrypt import batch_decrypt_files
from file_system.file_utils import format_file_size, list_files
from integrity.file_hash import compute_file_hashes, get_hash_records
from integrity.hash_compare import compare_files
from integrity.integrity_report import generate_integrity_report
from performance.performance_report import generate_performance_report


def clear_screen():
    """清屏"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title: str):
    """打印标题"""
    print("=" * 60)
    print(f"{title:^60}")
    print("=" * 60)


def print_menu(options: list, title: str = "菜单"):
    """
    打印菜单

    Args:
        options: 选项列表，每项为 (key, description) 元组
        title: 菜单标题
    """
    print(f"\n{'─' * 40}")
    print(f"  {title}")
    print(f"{'─' * 40}")
    for key, desc in options:
        print(f"  [{key}] {desc}")
    print(f"{'─' * 40}")


def wait_for_enter():
    """等待用户按回车键继续"""
    input("\n按回车键继续...")


def select_algorithm() -> str:
    """选择加密算法"""
    print("\n选择加密算法:")
    print("  [1] AES (高级加密标准，推荐)")
    print("  [2] DES (数据加密标准，用于性能对比)")
    choice = input("请选择 (1/2，默认 1): ").strip()
    return 'AES' if choice != '2' else 'DES'


def select_mode(algorithm: str) -> str:
    """选择加密模式"""
    modes = aes_supported_modes() if algorithm == 'AES' else des_supported_modes()
    print(f"\n选择 {algorithm} 加密模式:")
    for i, mode in enumerate(modes, 1):
        print(f"  [{i}] {mode}")
    choice = input(f"请选择 (1-{len(modes)}，默认 1): ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(modes):
            return modes[idx]
    except ValueError:
        pass
    return 'CBC'


def select_key_size() -> int:
    """选择 AES 密钥长度"""
    print("\n选择 AES 密钥长度:")
    print("  [1] 128 位")
    print("  [2] 192 位")
    print("  [3] 256 位 (推荐)")
    choice = input("请选择 (1-3，默认 3): ").strip()
    sizes = {1: 128, 2: 192, 3: 256}
    try:
        return sizes.get(int(choice), 256)
    except (ValueError, KeyError):
        return 256


def get_key_from_manager(km: KeyManager) -> tuple:
    """从密钥管理器获取密钥"""
    keys = km.list_keys()
    if not keys:
        print("\n当前没有可用密钥，请先生成密钥。")
        return None, None

    print(f"\n当前可用密钥 ({len(keys)} 个):")
    key_names = list(keys.keys())
    for i, name in enumerate(key_names, 1):
        info = keys[name]
        print(f"  [{i}] {name} ({info['algorithm']}-{info['key_size']})")

    choice = input(f"请选择密钥 (1-{len(key_names)}): ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(key_names):
            name = key_names[idx]
            key_bytes = km.get_key(name)
            return name, key_bytes
    except (ValueError, IndexError):
        pass
    return None, None


# ─── 用户登录/注册菜单 ───

def login_menu(login: Login, register: Register) -> bool:
    """登录菜单"""
    while True:
        clear_screen()
        print_header("Secure AES 加密系统 - 用户认证")
        print_menu([
            ('1', '登录'),
            ('2', '注册'),
            ('3', '查看密码强度检测'),
            ('0', '退出系统'),
        ], "请选择操作")

        choice = input("\n请输入选项: ").strip()

        if choice == '1':
            # 登录
            print("\n── 用户登录 ──")
            username = input("用户名: ").strip()
            password = input("密码: ").strip()
            result = login.login(username, password)
            print(f"\n[{'✓' if result['success'] else '✗'}] {result['message']}")
            if result['success']:
                wait_for_enter()
                return True
            wait_for_enter()

        elif choice == '2':
            # 注册
            print("\n── 用户注册 ──")
            username = input("用户名: ").strip()
            password = input("密码: ").strip()
            confirm = input("确认密码: ").strip()

            # 校验两次密码是否一致
            if password != confirm:
                print("\n[✗] 两次输入的密码不一致，请重新输入。")
                wait_for_enter()
                continue

            # 显示密码强度
            strength = check_password_strength(password)
            print(f"\n密码强度: {strength['level']} ({strength['score']}/100)")

            result = register.register(username, password)
            print(f"\n[{'✓' if result['success'] else '✗'}] {result['message']}")
            if not result['success'] and 'strength' in result:
                s = result['strength']
                print(f"密码强度: {s['level']} ({s['score']}/100)")
                for fb in s['feedback'][:3]:
                    print(f"  - {fb}")
            wait_for_enter()

        elif choice == '3':
            # 密码强度检测
            print("\n── 密码强度检测 ──")
            password = input("请输入要检测的密码: ").strip()
            strength = check_password_strength(password)
            print(f"\n评分: {strength['score']}/100")
            print(f"等级: {strength['level']}")
            if strength['feedback']:
                print("建议:")
                for fb in strength['feedback']:
                    print(f"  - {fb}")

            # 生成强密码
            print("\n── 推荐强密码 ──")
            strong_pwd = generate_strong_password()
            print(f"  生成的强密码: {strong_pwd}")
            s2 = check_password_strength(strong_pwd)
            print(f"  强度: {s2['level']} ({s2['score']}/100)")
            wait_for_enter()

        elif choice == '0':
            print("\n感谢使用 Secure AES 加密系统！")
            sys.exit(0)


# ─── 主功能菜单 ───

def main_menu(login: Login):
    """主功能菜单"""
    km = KeyManager()
    username = login.get_current_user()

    while True:
        clear_screen()
        print_header(f"Secure AES 加密系统 - 欢迎您，{username}")
        print_menu([
            ('1', '文件加密'),
            ('2', '文件解密'),
            ('3', '批量加密'),
            ('4', '批量解密'),
            ('5', '密钥管理'),
            ('6', '文件完整性校验'),
            ('7', '加密性能测试'),
            ('8', '查看日志'),
            ('0', '退出登录'),
        ], "主菜单")

        choice = input("\n请输入选项: ").strip()

        if choice == '1':
            file_encrypt_menu(km)
        elif choice == '2':
            file_decrypt_menu(km)
        elif choice == '3':
            batch_encrypt_menu(km)
        elif choice == '4':
            batch_decrypt_menu(km)
        elif choice == '5':
            key_management_menu(km)
        elif choice == '6':
            integrity_menu()
        elif choice == '7':
            performance_menu()
        elif choice == '8':
            view_logs_menu()
        elif choice == '0':
            login.logout()
            break


# ─── 文件加密 ───

def file_encrypt_menu(km: KeyManager):
    """文件加密菜单"""
    clear_screen()
    print_header("文件加密")

    input_file = input("请输入要加密的文件路径: ").strip()
    if not os.path.exists(input_file):
        print(f"\n[✗] 文件不存在: {input_file}")
        wait_for_enter()
        return

    # 文件信息
    file_size = os.path.getsize(input_file)
    print(f"\n文件信息: {os.path.basename(input_file)} ({format_file_size(file_size)})")

    algorithm = select_algorithm()
    mode = select_mode(algorithm)
    key_size = select_key_size() if algorithm == 'AES' else 56

    # 密钥选择
    print("\n密钥来源:")
    print("  [1] 使用已有密钥")
    print("  [2] 生成新密钥")
    key_choice = input("请选择 (1/2，默认 2): ").strip()

    key = None
    key_name = None

    if key_choice == '1':
        key_name, key = get_key_from_manager(km)
        if key is None:
            wait_for_enter()
            return
    else:
        if algorithm == 'AES':
            key_info = km.generate_aes_key(key_size)
            key = km.get_key(key_info['name'])
            key_name = key_info['name']
        else:
            key_info = km.generate_des_key()
            key = km.get_key(key_info['name'])
            key_name = key_info['name']
        print(f"\n[✓] 已生成新密钥: {key_name}")

    try:
        result = encrypt_single_file(input_file, algorithm, mode, key, key_size=key_size)
        print(f"\n[✓] 文件加密成功!")
        print(f"  输出文件: {result['output_file']}")
        print(f"  原文件大小: {result['original_size_fmt']}")
        print(f"  加密后大小: {result['encrypted_size_fmt']}")
        print(f"  密钥名称: {key_name}")
        print(f"  算法: {algorithm}, 模式: {mode}")
        if algorithm == 'AES':
            print(f"  密钥长度: {key_size} 位")
    except Exception as e:
        print(f"\n[✗] 加密失败: {e}")

    wait_for_enter()


# ─── 文件解密 ───

def file_decrypt_menu(km: KeyManager):
    """文件解密菜单"""
    clear_screen()
    print_header("文件解密")

    input_file = input("请输入要解密的文件路径: ").strip()
    if not os.path.exists(input_file):
        print(f"\n[✗] 文件不存在: {input_file}")
        wait_for_enter()
        return

    file_size = os.path.getsize(input_file)
    print(f"\n文件信息: {os.path.basename(input_file)} ({format_file_size(file_size)})")

    algorithm = select_algorithm()
    mode = select_mode(algorithm)

    # 获取密钥
    key_name, key = get_key_from_manager(km)
    if key is None:
        print("\n[✗] 未选择有效密钥，解密失败。")
        wait_for_enter()
        return

    try:
        result = decrypt_single_file(input_file, key, algorithm, mode)
        print(f"\n[✓] 文件解密成功!")
        print(f"  输出文件: {result['output_file']}")
        print(f"  加密文件大小: {result['encrypted_size_fmt']}")
        print(f"  解密后大小: {result['decrypted_size_fmt']}")
        print(f"  算法: {algorithm}, 模式: {mode}")
    except Exception as e:
        print(f"\n[✗] 解密失败: {e}")
        print("  可能原因: 密钥不正确、模式不匹配或文件已损坏。")

    wait_for_enter()


# ─── 批量加密 ───

def batch_encrypt_menu(km: KeyManager):
    """批量加密菜单"""
    clear_screen()
    print_header("批量文件加密")

    print("加密方式:")
    print("  [1] 加密指定文件列表")
    print("  [2] 加密整个目录")
    choice = input("请选择 (1/2): ").strip()

    algorithm = select_algorithm()
    mode = select_mode(algorithm)
    key_size = select_key_size() if algorithm == 'AES' else 56

    # 密钥
    key_name, key = get_key_from_manager(km)
    if key is None:
        key_info = km.generate_aes_key(key_size) if algorithm == 'AES' else km.generate_des_key()
        key = km.get_key(key_info['name'])
        key_name = key_info['name']
        print(f"\n[✓] 已生成新密钥: {key_name}")

    files = []

    if choice == '1':
        print("\n请输入要加密的文件路径（每行一个，空行结束）:")
        while True:
            f = input("  ").strip()
            if not f:
                break
            if os.path.exists(f):
                files.append(f)
            else:
                print(f"  [✗] 文件不存在: {f}")
    else:
        directory = input("\n请输入目录路径: ").strip()
        if os.path.isdir(directory):
            ext_input = input("请输入文件扩展名过滤（逗号分隔，如 .txt,.docx，直接回车不过滤）: ").strip()
            extensions = [e.strip() if e.startswith('.') else f'.{e.strip()}'
                          for e in ext_input.split(',') if e.strip()] if ext_input else None
            files = list_files(directory, extensions)
            print(f"\n找到 {len(files)} 个文件")
        else:
            print(f"\n[✗] 目录不存在: {directory}")
            wait_for_enter()
            return

    if not files:
        print("\n[✗] 没有需要加密的文件。")
        wait_for_enter()
        return

    print(f"\n开始批量加密 {len(files)} 个文件...")
    results = batch_encrypt_files(files, algorithm, mode, key, key_size=key_size)

    success = sum(1 for r in results if r['status'] == 'success')
    failed = sum(1 for r in results if r['status'] == 'failed')
    print(f"\n批量加密完成: 成功 {success}, 失败 {failed}")
    for r in results:
        status = '✓' if r['status'] == 'success' else '✗'
        if r['status'] == 'success':
            print(f"  [{status}] {os.path.basename(r['input_file'])} -> {os.path.basename(r['output_file'])}")
        else:
            print(f"  [{status}] {os.path.basename(r.get('input_file', ''))}: {r.get('error', '')}")

    wait_for_enter()


# ─── 批量解密 ───

def batch_decrypt_menu(km: KeyManager):
    """批量解密菜单"""
    clear_screen()
    print_header("批量文件解密")

    algorithm = select_algorithm()
    mode = select_mode(algorithm)

    key_name, key = get_key_from_manager(km)
    if key is None:
        print("\n[✗] 未选择有效密钥。")
        wait_for_enter()
        return

    print("\n解密方式:")
    print("  [1] 解密指定文件列表")
    print("  [2] 解密整个目录")
    choice = input("请选择 (1/2): ").strip()

    files = []

    if choice == '1':
        print("\n请输入要解密的文件路径（每行一个，空行结束）:")
        while True:
            f = input("  ").strip()
            if not f:
                break
            if os.path.exists(f):
                files.append(f)
            else:
                print(f"  [✗] 文件不存在: {f}")
    else:
        directory = input("\n请输入目录路径: ").strip()
        if os.path.isdir(directory):
            files = list_files(directory)
            print(f"找到 {len(files)} 个文件")
        else:
            print(f"\n[✗] 目录不存在: {directory}")
            wait_for_enter()
            return

    if not files:
        print("\n[✗] 没有需要解密的文件。")
        wait_for_enter()
        return

    print(f"\n开始批量解密 {len(files)} 个文件...")
    results = batch_decrypt_files(files, key, algorithm, mode)

    success = sum(1 for r in results if r['status'] == 'success')
    failed = sum(1 for r in results if r['status'] == 'failed')
    print(f"\n批量解密完成: 成功 {success}, 失败 {failed}")
    for r in results:
        status = '✓' if r['status'] == 'success' else '✗'
        if r['status'] == 'success':
            print(f"  [{status}] {os.path.basename(r['input_file'])} -> {os.path.basename(r['output_file'])}")
        else:
            print(f"  [{status}] {os.path.basename(r.get('input_file', ''))}: {r.get('error', '')}")

    wait_for_enter()


# ─── 密钥管理 ───

def key_management_menu(km: KeyManager):
    """密钥管理菜单"""
    while True:
        clear_screen()
        print_header("密钥管理")
        print_menu([
            ('1', '生成 AES 密钥'),
            ('2', '生成 DES 密钥'),
            ('3', '列出所有密钥'),
            ('4', '查看密钥详情'),
            ('5', '导出密钥（Base64）'),
            ('6', '导入密钥'),
            ('7', '删除密钥'),
            ('0', '返回主菜单'),
        ], "密钥管理")

        choice = input("\n请输入选项: ").strip()

        if choice == '1':
            key_size = select_key_size()
            key_info = km.generate_aes_key(key_size)
            print(f"\n[✓] AES 密钥已生成:")
            print(f"  名称: {key_info['name']}")
            print(f"  长度: {key_info['key_size']} 位")
            print(f"  创建时间: {key_info['created']}")
            wait_for_enter()

        elif choice == '2':
            key_info = km.generate_des_key()
            print(f"\n[✓] DES 密钥已生成:")
            print(f"  名称: {key_info['name']}")
            print(f"  长度: {key_info['key_size']} 位")
            print(f"  创建时间: {key_info['created']}")
            wait_for_enter()

        elif choice == '3':
            keys = km.list_keys()
            if not keys:
                print("\n当前没有可用密钥。")
            else:
                print(f"\n可用密钥 ({len(keys)} 个):")
                print(f"{'名称':<25} {'算法':<8} {'长度':<10} {'创建时间':<20}")
                print("-" * 63)
                for name, info in keys.items():
                    print(f"{name:<25} {info['algorithm']:<8} {info['key_size']:<10} {info['created']:<20}")
            wait_for_enter()

        elif choice == '4':
            key_name = input("\n请输入密钥名称: ").strip()
            info = km.get_key_info(key_name)
            if info:
                print(f"\n密钥详情:")
                for k, v in info.items():
                    if k == 'key_b64':
                        print(f"  {k}: {v[:32]}...")
                    else:
                        print(f"  {k}: {v}")
            else:
                print(f"\n[✗] 密钥不存在: {key_name}")
            wait_for_enter()

        elif choice == '5':
            key_name = input("\n请输入密钥名称: ").strip()
            key_b64 = km.export_key(key_name)
            if key_b64:
                print(f"\n密钥 {key_name} 的 Base64 编码:")
                print(f"  {key_b64}")
            else:
                print(f"\n[✗] 密钥不存在: {key_name}")
            wait_for_enter()

        elif choice == '6':
            print("\n── 导入密钥 ──")
            key_name = input("密钥名称: ").strip()
            key_b64 = input("密钥 Base64 编码: ").strip()
            print("算法类型: [1] AES  [2] DES")
            algo_choice = input("请选择 (1/2): ").strip()
            algorithm = 'AES' if algo_choice != '2' else 'DES'
            key_size = 256 if algorithm == 'AES' else 56
            if algorithm == 'AES':
                ks_choice = input("密钥长度 (128/192/256，默认 256): ").strip()
                if ks_choice in ('128', '192', '256'):
                    key_size = int(ks_choice)
            try:
                info = km.import_key(key_b64, key_name, algorithm, key_size)
                print(f"\n[✓] 密钥导入成功: {info['name']}")
            except Exception as e:
                print(f"\n[✗] 导入失败: {e}")
            wait_for_enter()

        elif choice == '7':
            key_name = input("\n请输入要删除的密钥名称: ").strip()
            confirm = input(f"确认删除密钥 '{key_name}'? (y/N): ").strip().lower()
            if confirm == 'y':
                if km.delete_key(key_name):
                    print(f"\n[✓] 密钥已删除: {key_name}")
                else:
                    print(f"\n[✗] 密钥不存在: {key_name}")
            else:
                print("\n已取消删除。")
            wait_for_enter()

        elif choice == '0':
            break


# ─── 完整性校验 ───

def integrity_menu():
    """完整性校验菜单"""
    while True:
        clear_screen()
        print_header("文件完整性校验")
        print_menu([
            ('1', '计算文件哈希值'),
            ('2', '比较原文件与解密文件哈希'),
            ('3', '生成完整性校验报告'),
            ('4', '查看历史校验记录'),
            ('0', '返回主菜单'),
        ], "完整性校验")

        choice = input("\n请输入选项: ").strip()

        if choice == '1':
            file_path = input("\n请输入文件路径: ").strip()
            if not os.path.exists(file_path):
                print(f"\n[✗] 文件不存在")
                wait_for_enter()
                continue

            hashes = compute_file_hashes(file_path)
            if hashes:
                print(f"\n文件: {hashes['file_name']}")
                print(f"大小: {hashes['file_size_fmt']}")
                print(f"MD5  : {hashes['md5']}")
                print(f"SHA1 : {hashes['sha1']}")
                print(f"SHA256: {hashes['sha256']}")
            wait_for_enter()

        elif choice == '2':
            orig = input("\n原始文件路径: ").strip()
            dec = input("解密文件路径: ").strip()
            if not os.path.exists(orig) or not os.path.exists(dec):
                print("\n[✗] 文件不存在")
                wait_for_enter()
                continue

            result = compare_files(orig, dec)
            print(f"\n哈希对比结果:")
            for algo, data in result['algorithms'].items():
                status = '✓ 一致' if data['match'] else '✗ 不一致'
                print(f"  {algo}: {status}")
            print(f"\n总体结果: {'✓ 完整性校验通过' if result['match'] else '✗ 完整性校验失败'}")
            wait_for_enter()

        elif choice == '3':
            orig = input("\n原始文件路径: ").strip()
            dec = input("解密文件路径: ").strip()
            if not os.path.exists(orig) or not os.path.exists(dec):
                print("\n[✗] 文件不存在")
                wait_for_enter()
                continue

            report_file = generate_integrity_report(orig, dec)
            print(f"\n[✓] 完整性校验报告已生成: {report_file}")
            print("\n报告预览:")
            with open(report_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            print(''.join(lines[:15]))
            wait_for_enter()

        elif choice == '4':
            records = get_hash_records()
            if not records:
                print("\n暂无历史校验记录。")
            else:
                print(f"\n历史校验记录 ({len(records)} 条):")
                for i, rec in enumerate(records[-10:], 1):
                    print(f"  {i}. {rec.get('file_name', 'N/A')} "
                          f"({rec.get('file_size_fmt', 'N/A')}) "
                          f"[{rec.get('timestamp', 'N/A')}]")
                    print(f"     SHA256: {rec.get('sha256', 'N/A')[:32]}...")
            wait_for_enter()

        elif choice == '0':
            break


# ─── 性能测试 ───

def performance_menu():
    """性能测试菜单"""
    clear_screen()
    print_header("加密性能测试")
    print("本测试将对比 AES 与 DES 在不同模式下的加解密性能。")
    print()

    # 选择测试数据
    print("选择测试数据:")
    print("  [1] 使用测试文件 (test_data/)")
    print("  [2] 使用指定文件")
    print("  [3] 生成随机测试数据")
    choice = input("请选择 (1/2/3，默认 1): ").strip()

    test_data = None

    if choice == '2':
        file_path = input("请输入文件路径: ").strip()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                test_data = f.read()
        else:
            print(f"\n[✗] 文件不存在")
            wait_for_enter()
            return
    elif choice == '3':
        size_str = input("请输入测试数据大小 (KB，默认 1024): ").strip()
        try:
            size = int(size_str) * 1024 if size_str else 1024 * 1024
        except ValueError:
            size = 1024 * 1024
        test_data = os.urandom(size)
        print(f"已生成 {size / 1024:.0f} KB 随机测试数据")
    else:
        # 使用 test_data 目录中的文件
        test_files = list_files(TEST_DATA_DIR)
        if test_files:
            print("\n可用的测试文件:")
            for i, f in enumerate(test_files, 1):
                size = os.path.getsize(f)
                print(f"  [{i}] {os.path.basename(f)} ({format_file_size(size)})")
            file_choice = input(f"请选择 (1-{len(test_files)}): ").strip()
            try:
                idx = int(file_choice) - 1
                if 0 <= idx < len(test_files):
                    with open(test_files[idx], 'rb') as f:
                        test_data = f.read()
            except (ValueError, IndexError):
                pass

        if test_data is None:
            # 默认使用 small.txt
            small_file = os.path.join(TEST_DATA_DIR, 'small.txt')
            if os.path.exists(small_file):
                with open(small_file, 'rb') as f:
                    test_data = f.read()
            else:
                test_data = os.urandom(1024 * 100)  # 100KB 默认数据

    if test_data is None or len(test_data) == 0:
        test_data = os.urandom(1024 * 100)
        print("使用 100KB 默认测试数据")

    print(f"\n测试数据大小: {format_file_size(len(test_data))}")
    print("\n开始性能测试，请稍候...")

    try:
        report_file = generate_performance_report(test_data)
        print(f"\n[✓] 性能测试完成！")
        print(f"\n报告已生成: {report_file}")
        print("\n测试结果摘要:")
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        # 打印报告的前半部分（AES 和 DES 结果）
        lines = content.split('\n')
        print('\n'.join(lines[:20]))
        print("...")
        print('\n'.join(lines[20:35]))
    except Exception as e:
        print(f"\n[✗] 性能测试失败: {e}")
        import traceback
        traceback.print_exc()

    wait_for_enter()


# ─── 查看日志 ───

def view_logs_menu():
    """查看日志菜单"""
    clear_screen()
    print_header("系统操作日志")

    lines = input("请输入要查看的日志行数 (默认 30): ").strip()
    try:
        n = int(lines) if lines else 30
    except ValueError:
        n = 30

    logs = get_recent_logs(n)
    if logs:
        print(f"\n最近 {len(logs)} 条日志记录:\n")
        for log_line in logs:
            print(log_line)
    else:
        print("\n暂无日志记录。")

    wait_for_enter()


# ─── 程序入口 ───

def main():
    """程序主入口"""
    login = Login()
    register = Register()

    # 初始化：确保目录存在
    for d in [ENCRYPTED_DIR, DECRYPTED_DIR, REPORTS_DIR]:
        os.makedirs(d, exist_ok=True)

    log_operation('system', 'Secure AES 加密系统启动')

    # 登录/注册
    if not login_menu(login, register):
        return

    # 进入主菜单
    main_menu(login)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已中断。")
        sys.exit(0)
    except Exception as e:
        print(f"\n程序异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
