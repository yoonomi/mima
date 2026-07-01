"""
操作日志记录模块
记录系统运行过程中的所有操作日志
"""

import os
import sys
import logging
from datetime import datetime
from typing import Optional

from config import LOG_DIR


# 日志文件路径（PyInstaller 打包后使用可写路径）
if getattr(sys, 'frozen', False):
    # 在 EXE 所在目录创建 logs 文件夹
    LOG_FILE = os.path.join(os.path.dirname(sys.executable), 'logs', 'operation.log')
else:
    LOG_FILE = os.path.join(LOG_DIR, 'operation.log')


def setup_logger() -> logging.Logger:
    """
    设置全局日志记录器

    Returns:
        配置好的日志记录器
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger('SecureAES')
    logger.setLevel(logging.INFO)

    # 避免重复添加 handler
    if not logger.handlers:
        # 文件处理器
        file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a')
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_formatter = logging.Formatter(
            '[%(asctime)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


def log_operation(action: str, detail: str, extra: str = None):
    """
    记录操作日志

    Args:
        action: 操作类型
        detail: 操作详情
        extra: 附加信息
    """
    logger = setup_logger()
    message = f"[{action}] {detail}"
    if extra:
        message += f" | {extra}"
    logger.info(message)


def get_recent_logs(lines: int = 20) -> list:
    """
    获取最近的日志记录

    Args:
        lines: 获取的行数

    Returns:
        日志行列表
    """
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
        return [line.strip() for line in all_lines[-lines:]]
    except (IOError, UnicodeDecodeError):
        return []


def clear_logs():
    """清空日志文件"""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('')
        log_operation('system', '日志已清空')
        return True
    except IOError:
        return False
