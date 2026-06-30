"""
密码强度检测模块
评估用户密码的安全强度并给出评分和建议
"""

import re
from typing import Dict, List, Tuple


class PasswordStrength:
    """密码强度等级"""
    VERY_WEAK = '非常弱'
    WEAK = '弱'
    MEDIUM = '中等'
    STRONG = '强'
    VERY_STRONG = '非常强'


def check_password_strength(password: str) -> Dict:
    """
    检测密码强度

    Args:
        password: 待检测的密码字符串

    Returns:
        包含评分、等级、建议的字典
    """
    score = 0
    feedback = []

    if len(password) == 0:
        return {
            'score': 0,
            'level': PasswordStrength.VERY_WEAK,
            'feedback': ['密码不能为空'],
        }

    # 长度评分
    length = len(password)
    if length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 10
    else:
        score += 5
        feedback.append('密码长度过短，建议至少8个字符')

    # 包含大写字母
    if re.search(r'[A-Z]', password):
        score += 15
    else:
        feedback.append('建议包含大写字母')

    # 包含小写字母
    if re.search(r'[a-z]', password):
        score += 15
    else:
        feedback.append('建议包含小写字母')

    # 包含数字
    if re.search(r'\d', password):
        score += 15
    else:
        feedback.append('建议包含数字')

    # 包含特殊字符
    if re.search(r'[!@#$%^&*(),.?":{}|<>_~`\-=+\[\];\\/]', password):
        score += 20
    else:
        feedback.append('建议包含特殊字符')

    # 字符种类多样性
    unique_chars = len(set(password))
    if unique_chars > length * 0.7:
        score += 10

    # 检查常见模式
    common_patterns = [
        r'(.)\1{2,}',        # 连续重复字符
        r'(123|abc|qwerty|password|admin|iloveyou|letmein)',
        r'^\d+$',            # 纯数字
        r'^[a-zA-Z]+$',      # 纯字母
    ]
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            score -= 10
            feedback.append('避免使用常见模式或重复字符')

    # 确定等级
    score = max(0, min(100, score))
    if score >= 90:
        level = PasswordStrength.VERY_STRONG
    elif score >= 70:
        level = PasswordStrength.STRONG
    elif score >= 50:
        level = PasswordStrength.MEDIUM
    elif score >= 25:
        level = PasswordStrength.WEAK
    else:
        level = PasswordStrength.VERY_WEAK

    return {
        'score': score,
        'level': level,
        'feedback': feedback,
    }


def check_password_entropy(password: str) -> float:
    """
    计算密码的信息熵

    Args:
        password: 待检测的密码

    Returns:
        信息熵值（比特）
    """
    if len(password) == 0:
        return 0.0

    char_pool_size = 0
    if re.search(r'[a-z]', password):
        char_pool_size += 26
    if re.search(r'[A-Z]', password):
        char_pool_size += 26
    if re.search(r'\d', password):
        char_pool_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>_~`\-=+\[\];\\/]', password):
        char_pool_size += 32

    if char_pool_size == 0:
        return 0.0

    entropy = len(password) * (char_pool_size.bit_length())
    return entropy


def generate_strong_password(length: int = 16) -> str:
    """
    生成强密码

    Args:
        length: 密码长度

    Returns:
        生成的强密码字符串
    """
    import string
    import secrets

    if length < 8:
        length = 8

    # 确保包含所有字符类型
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # 至少各一个
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # 填充剩余长度
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))

    # 打乱顺序
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)
