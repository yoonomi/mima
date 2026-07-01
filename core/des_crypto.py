"""
DES 加密与解密模块
用于与 AES 进行性能对比
支持 ECB、CBC 两种工作模式
"""

import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# DES 支持的工作模式
DES_MODES = {
    'ECB': DES.MODE_ECB,
    'CBC': DES.MODE_CBC,
}


def get_supported_modes() -> list:
    """获取支持的加密模式列表"""
    return list(DES_MODES.keys())


def generate_key() -> bytes:
    """
    生成 DES 密钥（8字节）
    DES 密钥长度为 56 位有效位 + 8 位奇偶校验位
    """
    return get_random_bytes(8)


def encrypt(plaintext: bytes, key: bytes, mode: str = 'CBC', iv: bytes = None) -> dict:
    """
    DES 加密

    Args:
        plaintext: 明文数据
        key: 密钥（8字节）
        mode: 加密模式 (ECB, CBC)
        iv: 初始向量

    Returns:
        包含密文、iv、模式等信息的字典
    """
    if mode not in DES_MODES:
        raise ValueError(f"不支持的加密模式: {mode}，可选 {list(DES_MODES.keys())}")

    cipher_mode = DES_MODES[mode]

    if mode == 'ECB':
        cipher = DES.new(key, cipher_mode)
        result_iv = b''
    else:
        if iv is None:
            iv = get_random_bytes(DES.block_size)
        cipher = DES.new(key, cipher_mode, iv=iv)
        result_iv = iv

    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

    return {
        'ciphertext': ciphertext,
        'iv': result_iv,
        'mode': mode,
    }


def decrypt(ciphertext: bytes, key: bytes, mode: str = 'CBC', iv: bytes = None) -> bytes:
    """
    DES 解密

    Args:
        ciphertext: 密文数据
        key: 密钥（8字节）
        mode: 加密模式 (ECB, CBC)
        iv: 初始向量

    Returns:
        解密后的明文数据
    """
    if mode not in DES_MODES:
        raise ValueError(f"不支持的加密模式: {mode}，可选 {list(DES_MODES.keys())}")

    cipher_mode = DES_MODES[mode]

    if mode == 'ECB':
        cipher = DES.new(key, cipher_mode)
    else:
        if iv is None:
            raise ValueError("CBC 模式需要提供 IV")
        cipher = DES.new(key, cipher_mode, iv=iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    except (ValueError, IndexError, TypeError) as e:
        raise ValueError(
            f"DES 解密失败：密钥不正确或数据已损坏 "
            f"(填充校验错误: {e})"
        ) from e
    return plaintext


def encrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC') -> dict:
    """
    DES 加密文件

    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        key: 密钥
        mode: 加密模式

    Returns:
        加密结果信息
    """
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    result = encrypt(plaintext, key, mode)

    with open(output_file, 'wb') as f:
        if mode != 'ECB':
            f.write(result['iv'])
        f.write(result['ciphertext'])

    return result


def decrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC') -> bytes:
    """
    DES 解密文件

    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        key: 密钥
        mode: 加密模式

    Returns:
        解密后的明文数据
    """
    with open(input_file, 'rb') as f:
        data = f.read()

    if mode == 'ECB':
        iv = None
        ciphertext = data
    else:
        iv = data[:DES.block_size]
        ciphertext = data[DES.block_size:]

    plaintext = decrypt(ciphertext, key, mode, iv)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    return plaintext
