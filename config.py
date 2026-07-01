"""
全局配置文件
定义项目的路径配置和全局常量
"""

import os
import sys


# 项目根目录（兼容 PyInstaller 打包环境）
if getattr(sys, 'frozen', False):
    # PyInstaller 打包后，数据文件在 sys._MEIPASS 目录下
    ROOT_DIR = sys._MEIPASS
else:
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# 各模块目录
CORE_DIR = os.path.join(ROOT_DIR, 'core')
FILE_SYSTEM_DIR = os.path.join(ROOT_DIR, 'file_system')
AUTH_DIR = os.path.join(ROOT_DIR, 'auth')
INTEGRITY_DIR = os.path.join(ROOT_DIR, 'integrity')
PERFORMANCE_DIR = os.path.join(ROOT_DIR, 'performance')
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
DATABASE_DIR = os.path.join(ROOT_DIR, 'database')
TEST_DATA_DIR = os.path.join(ROOT_DIR, 'test_data')
ENCRYPTED_DIR = os.path.join(ROOT_DIR, 'encrypted')
DECRYPTED_DIR = os.path.join(ROOT_DIR, 'decrypted')
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports')
SCREENSHOTS_DIR = os.path.join(ROOT_DIR, 'screenshots')
DOCS_DIR = os.path.join(ROOT_DIR, 'docs')

# AES 默认配置
AES_DEFAULT_KEY_SIZE = 256
AES_DEFAULT_MODE = 'CBC'
AES_SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']

# DES 默认配置
DES_DEFAULT_MODE = 'CBC'
DES_SUPPORTED_MODES = ['ECB', 'CBC']

# 哈希算法
HASH_ALGORITHMS = ['MD5', 'SHA1', 'SHA256']

# 文件大小限制（单文件最大 500MB）
MAX_FILE_SIZE = 500 * 1024 * 1024

# 密码强度最低要求
MIN_PASSWORD_SCORE = 50
