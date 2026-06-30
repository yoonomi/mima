"""
AES 加密与解密模块
使用 PyCryptodome 库实现 AES 加密和解密功能
支持 ECB、CBC、CFB、OFB、CTR 五种工作模式
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# AES 支持的工作模式
AES_MODES = {
    'ECB': AES.MODE_ECB,
    'CBC': AES.MODE_CBC,
    'CFB': AES.MODE_CFB,
    'OFB': AES.MODE_OFB,
    'CTR': AES.MODE_CTR,
}


def get_supported_modes() -> list:
    """获取支持的加密模式列表"""
    return list(AES_MODES.keys())


def generate_key(key_size: int = 256) -> bytes:
    """
    生成 AES 密钥

    Args:
        key_size: 密钥长度，可选 128, 192, 256

    Returns:
        生成的密钥字节串
    """
    if key_size not in (128, 192, 256):
        raise ValueError(f"不支持的密钥长度: {key_size}，可选 128、192、256")
    return get_random_bytes(key_size // 8)


def encrypt(plaintext: bytes, key: bytes, mode: str = 'CBC', iv: bytes = None) -> dict:
    """
    AES 加密

    Args:
        plaintext: 明文数据
        key: 密钥
        mode: 加密模式 (ECB, CBC, CFB, OFB, CTR)
        iv: 初始向量，不提供则自动生成

    Returns:
        包含密文、iv、模式等信息的字典
    """
    if mode not in AES_MODES:
        raise ValueError(f"不支持的加密模式: {mode}，可选 {list(AES_MODES.keys())}")

    cipher_mode = AES_MODES[mode]

    # 对于 ECB 模式不需要 IV
    if mode == 'ECB':
        cipher = AES.new(key, cipher_mode)
        result_iv = b''
    elif mode == 'CTR':
        # CTR 模式使用 nonce
        if iv is None:
            iv = get_random_bytes(8)
        cipher = AES.new(key, cipher_mode, nonce=iv)
        result_iv = iv
    else:
        # CBC、CFB、OFB 模式需要 IV
        if iv is None:
            iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, cipher_mode, iv=iv)
        result_iv = iv

    # 对明文进行填充（CTR 和 CFB 模式不需要填充）
    if mode in ('CTR', 'CFB'):
        ciphertext = cipher.encrypt(plaintext)
    else:
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return {
        'ciphertext': ciphertext,
        'iv': result_iv,
        'mode': mode,
        'key_size': len(key) * 8,
    }


def decrypt(ciphertext: bytes, key: bytes, mode: str = 'CBC', iv: bytes = None) -> bytes:
    """
    AES 解密

    Args:
        ciphertext: 密文数据
        key: 密钥
        mode: 加密模式 (ECB, CBC, CFB, OFB, CTR)
        iv: 初始向量

    Returns:
        解密后的明文数据
    """
    if mode not in AES_MODES:
        raise ValueError(f"不支持的加密模式: {mode}，可选 {list(AES_MODES.keys())}")

    cipher_mode = AES_MODES[mode]

    if mode == 'ECB':
        cipher = AES.new(key, cipher_mode)
    elif mode == 'CTR':
        if iv is None:
            raise ValueError("CTR 模式需要提供 nonce")
        cipher = AES.new(key, cipher_mode, nonce=iv)
    else:
        if iv is None:
            raise ValueError(f"{mode} 模式需要提供 IV")
        cipher = AES.new(key, cipher_mode, iv=iv)

    if mode in ('CTR', 'CFB'):
        plaintext = cipher.decrypt(ciphertext)
    else:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext


def encrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC') -> dict:
    """
    加密文件

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

    # 将 IV 和密文一起写入文件（前16字节为 IV）
    with open(output_file, 'wb') as f:
        if mode != 'ECB':
            if mode == 'CTR':
                # CTR 模式写入 nonce + 密文
                f.write(len(result['iv']).to_bytes(1, 'big'))
                f.write(result['iv'])
            else:
                f.write(result['iv'])
        f.write(result['ciphertext'])

    return result


def decrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC') -> bytes:
    """
    解密文件

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
    elif mode == 'CTR':
        iv_len = data[0]
        iv = data[1:1 + iv_len]
        ciphertext = data[1 + iv_len:]
    else:
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]

    plaintext = decrypt(ciphertext, key, mode, iv)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    return plaintext
