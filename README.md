# Secure AES 加密系统

## 基于对称密码体系的数据加密解密实现（DES、AES）

### 项目简介

本项目实现了一个基于对称密码体系的文件加密解密系统，支持 **AES**（高级加密标准）和 **DES**（数据加密标准）两种对称加密算法，提供文件加密、解密、密钥管理、完整性校验和性能测试等完整功能。

### 功能特性

- **用户认证系统**：注册、登录、密码强度检测
- **文件加密**：支持 AES（128/192/256位）和 DES（56位）加密
- **文件解密**：使用正确密钥解密加密文件
- **多种加密模式**：ECB、CBC、CFB、OFB、CTR
- **批量处理**：支持批量文件加密和解密
- **密钥管理**：生成、导入、导出、删除密钥
- **完整性校验**：MD5、SHA1、SHA256 哈希校验
- **性能测试**：AES 与 DES 性能对比分析
- **日志记录**：完整的操作日志

### 项目结构

```
Secure_AES_System/
├── main.py                 # 程序入口，命令行菜单
├── config.py               # 全局配置
├── requirements.txt        # 项目依赖
├── README.md               # 使用说明
├── core/                   # 核心安全算法模块
│   ├── aes_crypto.py       # AES 加密与解密
│   ├── des_crypto.py       # DES 加密与解密
│   ├── key_manager.py      # 密钥生成与管理
│   ├── password_checker.py # 密码强度检测
│   └── hash_utils.py       # 哈希函数
├── file_system/            # 文件处理模块
│   ├── file_encrypt.py     # 单文件加密
│   ├── file_decrypt.py     # 单文件解密
│   ├── batch_encrypt.py    # 批量加密
│   ├── batch_decrypt.py    # 批量解密
│   └── file_utils.py       # 文件工具函数
├── auth/                   # 用户认证模块
│   ├── login.py            # 用户登录
│   ├── register.py         # 用户注册
│   └── user_manager.py     # 用户管理
├── integrity/              # 完整性校验模块
│   ├── file_hash.py        # 文件哈希计算
│   ├── hash_compare.py     # 哈希对比
│   └── integrity_report.py # 校验报告
├── performance/            # 性能测试模块
│   ├── aes_benchmark.py    # AES 性能测试
│   ├── des_benchmark.py    # DES 性能测试
│   ├── compare_test.py     # 性能对比
│   └── performance_report.py # 测试报告
├── logs/                   # 日志模块
│   ├── logger.py           # 日志记录
│   └── operation.log       # 运行日志
├── database/               # 数据存储
│   ├── users.json          # 用户数据
│   ├── keys.json           # 密钥数据
│   ├── hash_records.json   # 哈希记录
│   └── performance_records.json # 性能记录
├── test_data/              # 测试数据
├── encrypted/              # 加密输出目录
├── decrypted/              # 解密输出目录
└── reports/                # 报告输出
```

### 安装说明

1. **安装 Python 依赖**

```bash
pip install -r requirements.txt
```

2. **运行程序**

```bash
python main.py
```

### 使用指南

#### 1. 用户注册与登录

首次使用需要注册账号：
- 输入用户名（至少3个字符）
- 输入密码（建议包含大小写字母、数字和特殊字符）
- 系统会自动检测密码强度，弱密码不允许注册

#### 2. 文件加密

1. 在主菜单中选择 [1] 文件加密
2. 输入要加密的文件路径
3. 选择加密算法（AES/DES）
4. 选择加密模式（ECB/CBC/CFB/OFB/CTR）
5. 选择密钥长度（AES: 128/192/256）
6. 选择密钥来源（已有密钥或生成新密钥）
7. 加密完成后，文件保存在 `encrypted/` 目录

#### 3. 文件解密

1. 在主菜单中选择 [2] 文件解密
2. 输入加密文件路径
3. 选择对应的算法和模式
4. 选择正确的密钥
5. 解密完成后，文件保存在 `decrypted/` 目录

#### 4. 密钥管理

- **生成密钥**：自动生成 AES 或 DES 密钥
- **列出密钥**：查看所有已保存的密钥
- **导入/导出**：支持 Base64 格式的密钥导入导出
- **删除密钥**：删除不再需要的密钥

#### 5. 完整性校验

使用 MD5、SHA1、SHA256 三种哈希算法验证文件完整性：
- 计算文件哈希值
- 比较原文件与解密文件的哈希值
- 生成完整性校验报告

#### 6. 性能测试

自动测试 AES 和 DES 在不同模式下的加解密性能：
- 测试所有加密模式
- 测试不同密钥长度
- 生成详细的性能对比报告

### 算法对比

| 特性 | AES | DES |
|------|-----|-----|
| 密钥长度 | 128/192/256 位 | 56 位 |
| 分组长度 | 128 位 | 64 位 |
| 安全性 | 高（当前安全） | 低（已爆破） |
| 速度 | 快 | 较慢 |
| 支持模式 | ECB/CBC/CFB/OFB/CTR | ECB/CBC |

### 注意事项

1. **密钥安全**：请妥善保管生成的密钥，丢失密钥将无法解密文件
2. **文件备份**：加密前建议备份原始文件
3. **密码安全**：使用强密码保护账户安全
4. **兼容性**：解密时必须使用与加密时相同的算法、模式和密钥

### 课程设计信息

- **题目**：基于对称密码体系的数据加密解密实现（DES、AES）
- **作者**：[学号] [姓名]
- **日期**：2026-06-30

### 参考资料

1. National Institute of Standards and Technology. (2001). Advanced Encryption Standard (AES)
2. Federal Information Processing Standards. (1977). Data Encryption Standard (DES)
3. Daemen, J., & Rijmen, V. (2002). The Design of Rijndael: AES - The Advanced Encryption Standard
