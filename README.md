<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PyQt5-桌面应用-brightgreen" alt="PyQt5">
  <img src="https://img.shields.io/badge/SQLCipher-解密-success" alt="SQLCipher">
  <img src="https://img.shields.io/badge/Protobuf-解码-blueviolet" alt="Protobuf">
  <img src="https://img.shields.io/badge/版本-v1.0-blue" alt="v1.0">
</p>

<h1 align="center">🐧 QQ 聊天记录导出工具</h1>

<p align="center">
  <strong>一键导出 QQ NT Windows 版聊天记录 · 支持 HTML / TXT 格式</strong>
</p>

---

## 这是什么

QQ NT Windows 版的聊天数据库使用 SQLCipher 加密存储，消息体使用 Protobuf 编码，无法直接读取。

这个工具可以**一键提取密钥 → 解密数据库 → 解码消息 → 导出聊天记录**，全过程可视化操作。

---

## ✨ 功能

- 🔑 **自动提取密钥** — 调试器断点截获 + 内存扫描双方案
- 🗄️ **解密 SQLCipher 数据库** — 支持自定义加密参数（PBKDF2、HMAC、迭代次数）
- 🔧 **Protobuf 消息解码** — 自研解码器解析 QQ NT 消息体
- 📤 **导出聊天记录** — HTML / TXT 两种格式
- 🖥️ **图形界面** — PyQt5 可视化操作，QQ 主题风格

---

## 📥 下载

已打包为可直接运行的 Windows 版本：

> [下载地址](https://wwbdf.lanzoum.com/b0j1gao2d)（提取码：bing）

下载解压后双击 `启动QQ导出工具.bat` 即可使用。

---

## 🚀 使用方式

### 方式一：直接运行打包版

```
1. 下载并解压
2. 双击 启动QQ导出工具.bat
3. 工具自动检测 QQ 安装目录 → 提取密钥 → 选择联系人 → 导出
```

### 方式二：源码运行

```bash
# 安装依赖
pip install PyQt5 pycryptodome sqlcipher3-binary

# 运行主程序
python qq_export_gui.py
```

---

## 🏗 技术原理

### 密钥提取（主方案：调试器法）

QQ NT 的数据库加密密钥由 `wrapper.node`（Electron Native 插件）管理。工具分析该 PE64 文件的 `.rdata` 段，定位密钥相关函数后，以调试模式启动 QQ：

```
分析 wrapper.node PE64 文件
    ↓
在 .rdata 段查找 "nt_sqlite3_key_v2: db=%p zDb=%s" 字符串
    ↓
通过 LEA 指令定位密钥处理函数地址
    ↓
以调试模式启动 QQ → 用户登录时断点触发
    ↓
从 R8 寄存器读取 16 位 ASCII 密钥
```

需要关闭已运行的 QQ，由工具以调试模式重新启动（用户需重新登录一次）。

### 密钥提取（备用方案：内存搜索法）

如果调试器法不可用，也可以直接从已运行的 QQ 进程内存中扫描密钥字符串。

### 数据库解密

QQ NT 数据库使用 SQLCipher，主要参数：

| 参数 | 值 |
|------|-----|
| 加密算法 | AES-256-CBC |
| 密钥派生 | PBKDF2_HMAC_SHA512 |
| KDF 迭代 | 4000 |
| HMAC | HMAC_SHA1 |
| 页面大小 | 4096 |

解密前自动检测并移除 NTQQ 自定义的 1024 字节文件头。

### Protobuf 消息解码

QQ NT 的消息体使用 Protobuf 格式编码。工具通过自定义 `_parse_protobuf_fields()` 函数，递归解析嵌套的 Protobuf 字段结构，提取消息内容、时间戳、发送人等信息。

---

## 📁 项目结构

```
qq_export/
├── qq_export_gui.py        # 主程序：PyQt5 图形界面 + 核心导出逻辑
├── extract_key.ps1         # PowerShell 调试器脚本（密钥提取）
├── qq_export.spec          # PyInstaller 打包配置
├── 启动QQ导出工具.bat       # Windows 一键启动
└── README.md
```

### 核心文件说明

| 文件 | 说明 |
|------|------|
| `qq_export_gui.py` | 完整桌面应用。`QQExporter` 类处理密钥提取/数据库解密/Protobuf 解码/聊天导出，`QQExportGUI` 类提供 PyQt5 操作界面 |
| `extract_key.ps1` | PowerShell 脚本。分析 `wrapper.node` PE64 文件，通过调试器断点从 R8 寄存器截获数据库密钥 |
| `qq_export.spec` | PyInstaller 打包配置（将 `extract_key.ps1` 作为数据文件打包） |

---

## 🔗 生态定位

```
QQ 聊天记录导出工具
        ↓
    TXT 文件
        ↓
  观己（AI 分析人生经历）
        ↓
  复制给茵茵 / 任何 AI
```

与微信导出工具一样，这个工具是整个链条的**数据源头**——把 QQ 里的聊天记录解放出来，让后续的 AI 分析和陪伴成为可能。

---

## 📜 许可证

MIT License

---

<p align="center">
  你的聊天记录属于你自己 · 工具本地运行 · 数据不上传(如果这个项目对你有启发，欢迎。如果有合作机会，联系微信：zhengtu920)
</p>
