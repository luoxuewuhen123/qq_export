# -*- coding: utf-8 -*-
"""
QQ聊天记录导出工具 v1.0 - 可视化版
支持QQ NT Windows版，一键提取密钥→解密→导出
与微信导出工具风格统一，QQ主题蓝色
"""
import sys
import os
import re
import json
import struct
import subprocess
import threading
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QProgressBar, QGroupBox,
    QFileDialog, QMessageBox, QCheckBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QStatusBar, QAbstractItemView, QSplitter, QComboBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer, QThread
from PyQt5.QtGui import QFont, QColor, QTextCursor

# ============ 常量 ============
# QQ NT字段映射
FIELD_MSG_ID = '40001'
FIELD_CHAT_TYPE = '40010'  # 1=私聊, 2=群聊
FIELD_PEER_UID = '40020'
FIELD_PEER_UIN = '40030'  # 对方QQ号/群号
FIELD_SENDER_UIN = '40033'  # 发送者QQ号
FIELD_TIMESTAMP = '40050'
FIELD_SENDER_NAME = '40090'
FIELD_BODY = '40800'  # Protobuf消息体
FIELD_MSG_FLAG = '40105'

MSG_TYPE_MAP = {
    1: "文本", 2: "图片", 3: "语音", 4: "视频", 5: "文件",
    6: "链接", 7: "表情", 8: "红包", 9: "名片",
    10: "位置", 11: "合并转发", 12: "拍一拍",
    13: "系统消息", 14: "撤回消息", 15: "群公告",
}


# ============ 信号中转 ============
class WorkerSignals(QObject):
    log = pyqtSignal(str, str)       # (message, level)
    progress = pyqtSignal(int, int)   # (current, total)
    step_done = pyqtSignal(str)       # step name
    all_done = pyqtSignal(bool, str)  # (success, message)
    chat_list = pyqtSignal(list)      # chat list for table


# ============ Protobuf解码器 ============
def _read_varint(data, pos, end):
    """读取一个varint，返回(value, new_pos)"""
    value = 0
    shift = 0
    while pos < end:
        b = data[pos]
        value |= (b & 0x7F) << shift
        shift += 7
        pos += 1
        if (b & 0x80) == 0:
            break
    return value, pos


def _parse_protobuf_fields(data, start=0, end=None):
    """解析Protobuf字节流，返回 {field_number: [(wire_type, value), ...]} 字典
    
    只解析一层，不递归嵌套消息。wire_type=0的value是int，wire_type=2的value是bytes。
    支持多字节varint编码的tag（field_number > 15时tag需要多个字节）。
    """
    if end is None:
        end = len(data)
    fields = {}
    i = start
    while i < end:
        if i >= end:
            break
        
        # tag本身也是varint编码（修复：支持field_number > 15）
        tag_val, i = _read_varint(data, i, end)
        wire_type = tag_val & 0x07
        field_number = tag_val >> 3
        
        if field_number == 0:
            break  # 无效field_number
        
        if wire_type == 0:  # Varint
            value, i = _read_varint(data, i, end)
            fields.setdefault(field_number, []).append((0, value))
        elif wire_type == 2:  # Length-delimited
            length, i = _read_varint(data, i, end)
            if length < 0 or i + length > end:
                break
            value = data[i:i+length]
            i += length
            fields.setdefault(field_number, []).append((2, value))
        elif wire_type == 1:  # 64-bit
            i += 8
        elif wire_type == 5:  # 32-bit
            i += 4
        else:
            break  # 未知wire_type，停止解析
    return fields


def decode_protobuf_text(body_bytes):
    """从Protobuf消息体中提取文本内容
    
    QQ NT消息体Protobuf实际结构（通过逆向分析确认）：
    
    body外层 {
        field 40800: bytes  消息元素（可重复出现，一条消息可有多个元素）
    }
    
    消息元素 (field 40800 的值) {
        field 45001: varint  消息ID
        field 45002: varint  消息类型 (1=文本, 2=图片, 3=语音, 4=视频, 5=文件, 6=链接, 7=表情, 8=红包, ...)
        field 45101: string 文本内容（文本消息时）
        field 45102: varint  未知标记
        field 45405: varint  图片宽度（图片消息时）
        field 45406: bytes   图片信息
        field 45411: varint  图片尺寸
        field 45412: varint  图片尺寸
        field 45503: bytes   媒体数据
        field 45509: varint  未知
    }
    
    策略：
    1. 解析body外层，获取所有field 40800的值
    2. 对每个消息元素，根据45002判断类型
    3. 文本消息：提取45101的文本
    4. 图片/视频/语音等：返回标记
    """
    if not body_bytes:
        return ""
    
    try:
        outer = _parse_protobuf_fields(body_bytes)
    except Exception:
        return ""
    
    # 获取所有消息元素（field 40800，可重复）
    msg_elements = outer.get(40800, [])
    
    if not msg_elements:
        return ""
    
    parts = []
    
    for wt, element_bytes in msg_elements:
        if wt != 2:
            continue
        
        try:
            element = _parse_protobuf_fields(element_bytes)
        except Exception:
            continue
        
        # 获取消息类型
        msg_type = 0
        if 45002 in element:
            for wt2, val in element[45002]:
                if wt2 == 0:
                    msg_type = val
                    break
        
        # 根据消息类型提取内容
        if msg_type == 1:
            # 文本消息：提取45101
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(t)
                        except:
                            pass
        elif msg_type == 2:
            # 图片
            parts.append("[图片]")
        elif msg_type == 3:
            # 语音
            parts.append("[语音]")
        elif msg_type == 4:
            # 视频
            parts.append("[视频]")
        elif msg_type == 5:
            # 文件
            parts.append("[文件]")
        elif msg_type == 6:
            # 链接
            # 尝试提取链接文本
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(t)
                        except:
                            pass
            else:
                parts.append("[链接]")
        elif msg_type == 7:
            # 表情
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(f"[{t}]")
                        except:
                            pass
            else:
                parts.append("[表情]")
        elif msg_type == 8:
            # 红包
            parts.append("[红包]")
        elif msg_type == 10:
            # 位置
            parts.append("[位置]")
        elif msg_type == 11:
            # 合并转发
            parts.append("[合并转发]")
        elif msg_type == 12:
            # 拍一拍
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(f"[拍一拍: {t}]")
                        except:
                            pass
            else:
                parts.append("[拍一拍]")
        elif msg_type == 13:
            # 系统消息
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(t)
                        except:
                            pass
        else:
            # 未知类型，尝试提取文本
            if 45101 in element:
                for wt2, val in element[45101]:
                    if wt2 == 2:
                        try:
                            t = val.decode('utf-8').strip()
                            if t:
                                parts.append(t)
                        except:
                            pass
    
    result = '\n'.join(parts)
    
    # 最终清理：过滤掉还是混进来的垃圾数据
    if result:
        clean_lines = []
        for line in result.split('\n'):
            line = line.strip()
            if not line:
                continue
            # 过滤Protobuf残留
            if line.startswith('OMPAT.') or line.startswith('COMPAT.') or line.startswith('TV2COMPAT.'):
                continue
            # 过滤图片下载URL
            if 'download?appid=' in line or 'spec=198' in line or 'spec=72' in line:
                continue
            # 过滤base64编码数据
            if len(line) > 50 and re.match(r'^[A-Za-z0-9+/=._\-]+$', line):
                continue
            # 过滤纯hex/md5哈希
            if re.match(r'^[a-f0-9]{32,}$', line):
                continue
            # 过滤QQ数据路径残留
            if line.startswith('QQ数据\\') or line.startswith('QQ数据/'):
                continue
            # 过滤multi-msg/分享等系统内容
            if 'multiMsg' in line or 'feedid' in line or 'shareentrance' in line:
                continue
            clean_lines.append(line)
        result = '\n'.join(clean_lines)
    
    return result


def is_valid_chat_message(text):
    """判断是否是有效的聊天消息（过滤系统消息和Protobuf残留）"""
    if not text or len(text.strip()) == 0:
        return False
    
    # 媒体标记是有效消息
    if text.strip() in ('[图片]', '[语音]', '[视频]', '[文件]', '[红包]', '[表情]'):
        return True
    
    # 过滤Protobuf残留数据（图片/表情/文件的base64编码元数据）
    protobuf_prefixes = ['OMPAT.', 'COMPAT.', 'TV2COMPAT.']
    for prefix in protobuf_prefixes:
        if prefix in text:
            return False
    
    # 过滤图片下载URL残留
    url_keywords = ['download?appid=', 'spec=198', 'spec=72', 'fileid=', 'multimsg']
    for kw in url_keywords:
        if kw in text:
            return False
    
    system_keywords = [
        '"app":', 'mailUrl', 'detailDesc', '"appID"',
        'tianquan.gtimg.cn', 'club.vip.qq.com',
        'wx.mail.qq.com', 'mqqapi://',
        'jump.html', 'login_jump',
        'bannerUrl', 'singlePic',
        'feedid', 'shareentrance', 'recomContentID',
        'qq-video.cdn-go.cn',
    ]
    
    for kw in system_keywords:
        if kw in text:
            return False
    
    # 过滤纯base64/URL编码的字符串（放宽正则以包含含.号的变体）
    if len(text) > 50 and re.match(r'^[A-Za-z0-9+/=._\-]+$', text):
        return False
    
    # 过滤图片文件名残留（如 "ږ.png" 等）
    if re.match(r'^[\x00-\x1f\x7f-\xff]*\.png$', text.strip()):
        return False
    
    # 过滤md5哈希值残留（如 "e9072887a1a1a10630ffb5e803388b9ca2820640d48603ر"）
    if re.match(r'^[a-f0-9]{32,}[^\x00-\x7f]*$', text.strip()):
        return False
    
    # 过滤QQ数据路径残留
    if text.strip().startswith('QQ数据\\') or text.strip().startswith('QQ数据/'):
        return False
    
    # 过滤纯hex字符串（32位以上，MD5/SHA等）
    if re.match(r'^[A-Fa-f0-9]{32,}$', text.strip()):
        return False
    
    return True


# ============ 核心逻辑 ============
class QQExporter:
    def __init__(self, signals: WorkerSignals, output_dir: str):
        self.signals = signals
        self.output_dir = output_dir
        self.chat_export_dir = os.path.join(output_dir, "chat_export")
        self.qq_data_dir = ""
        self.my_qq = ""
        self.key = ""
        self.clean_db_path = ""
        self.conn = None
        self.qq_install_dir = ""
    
    def log(self, msg, level="info"):
        self.signals.log.emit(msg, level)
    
    @staticmethod
    def _get_all_drives():
        """获取所有可用的磁盘驱动器号"""
        drives = []
        for mask in range(26):
            letter = chr(ord('A') + mask)
            path = f"{letter}:\\"
            if os.path.exists(path):
                drives.append(letter)
        return drives

    def find_qq_install_dir(self):
        """自动查找QQ安装目录（全盘扫描+注册表+进程+快捷方式）"""
        # === 方法1：从运行中的QQ进程路径获取（最准确） ===
        try:
            r = subprocess.run(
                ['wmic', 'process', 'where', 'name="QQ.exe"', 'get', 'ExecutablePath'],
                capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
            )
            for line in r.stdout.strip().split('\n'):
                line = line.strip()
                if line and line.endswith('QQ.exe') and os.path.exists(line):
                    install_dir = os.path.dirname(line)
                    self.log(f"进程找到QQ安装目录: {install_dir}")
                    return install_dir
        except:
            pass

        # === 方法2：从桌面快捷方式解析 ===
        desktop_dir = os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')
        common_desktop = os.path.join(os.environ.get('PUBLIC', ''), 'Desktop')
        for d in [desktop_dir, common_desktop]:
            if not os.path.exists(d):
                continue
            for f in os.listdir(d):
                if f.lower().endswith('.lnk') and 'qq' in f.lower():
                    try:
                        import win32com.client
                        shell = win32com.client.Dispatch("WScript.Shell")
                        shortcut = shell.CreateShortCut(os.path.join(d, f))
                        target = shortcut.TargetPath
                        if target and target.lower().endswith('qq.exe') and os.path.exists(target):
                            install_dir = os.path.dirname(target)
                            self.log(f"快捷方式找到QQ安装目录: {install_dir}")
                            return install_dir
                    except:
                        pass

        # === 方法3：注册表搜索（HKCU + HKLM） ===
        for hive in [r"HKCU\SOFTWARE", r"HKLM\SOFTWARE"]:
            for sub in [r"Microsoft\Windows\CurrentVersion\Uninstall",
                        r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
                try:
                    r = subprocess.run(
                        ["reg", "query", f"{hive}\\{sub}", "/s", "/f", "QQ"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10
                    )
                    for line in r.stdout.split('\n'):
                        if 'InstallLocation' in line and 'REG_SZ' in line:
                            path = line.split('REG_SZ')[-1].strip()
                            if path and os.path.exists(os.path.join(path, "QQ.exe")):
                                self.log(f"注册表找到QQ安装目录: {path}")
                                return path
                except:
                    pass

        # === 方法4：全盘扫描根目录和Program Files ===
        drives = self._get_all_drives()
        for letter in drives:
            # 直接在根目录找 QQNT 文件夹
            root_qqnt = f"{letter}:\\QQNT"
            if os.path.exists(os.path.join(root_qqnt, "QQ.exe")):
                self.log(f"全盘扫描找到QQ安装目录: {root_qqnt}")
                return root_qqnt
            # Program Files 下找
            for pf in [f"{letter}:\\Program Files\\QQNT", f"{letter}:\\Program Files (x86)\\QQNT"]:
                if os.path.exists(os.path.join(pf, "QQ.exe")):
                    self.log(f"全盘扫描找到QQ安装目录: {pf}")
                    return pf

        self.log("未找到QQ安装目录")
        return None
    
    def find_qq_data_dir(self, qq_number=""):
        """自动查找QQ数据目录（进程命令行+全盘扫描）
        
        Args:
            qq_number: 用户QQ号，传入时只返回精确匹配该QQ号的目录
        """
        
        # === 方法1：从运行中的QQ进程命令行提取数据路径（最准确） ===
        # QQ启动命令行通常包含 --data-path="D:\QQ数据\QQ号" 之类的参数
        try:
            r = subprocess.run(
                ['wmic', 'process', 'where', 'name="QQ.exe"', 'get', 'CommandLine'],
                capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
            )
            for line in r.stdout.strip().split('\n'):
                line = line.strip()
                # 提取 --data-path 参数
                m = re.search(r'--data-path[=\s]+"?([^"\s]+)"?', line)
                if m:
                    data_path = m.group(1)
                    # 可能是 D:\QQ数据\1243592024 或 D:\QQ数据 这种上级
                    if os.path.exists(data_path) and os.path.exists(os.path.join(data_path, "nt_qq")):
                        # 如果用户指定了QQ号，验证目录名是否匹配
                        if qq_number:
                            dirname = os.path.basename(data_path)
                            if dirname == qq_number:
                                self.log(f"进程命令行找到QQ数据目录: {data_path}")
                                return data_path
                            # 不匹配则跳过，继续搜索
                        else:
                            self.log(f"进程命令行找到QQ数据目录: {data_path}")
                            return data_path
                    # 可能传入的是上级目录，尝试在下面找QQ号子目录
                    if os.path.exists(data_path):
                        for d in os.listdir(data_path):
                            full = os.path.join(data_path, d)
                            if os.path.isdir(full) and os.path.exists(os.path.join(full, "nt_qq")):
                                if qq_number and d == qq_number:
                                    self.log(f"进程命令行找到QQ数据目录: {full}")
                                    return full
                                elif not qq_number and (d.isdigit() or (len(d) >= 5 and d[0].isdigit())):
                                    self.log(f"进程命令行找到QQ数据目录: {full}")
                                    return full
                # 也从可执行文件路径推断数据目录
                m2 = re.search(r'"([^"]+\\QQNT[^"]*\\QQ\.exe)"', line)
                if m2:
                    qq_install = os.path.dirname(m2.group(1))
                    parent = os.path.dirname(qq_install)
                    for candidate in [os.path.join(parent, "QQ数据"), os.path.join(parent, "Tencent Files")]:
                        if os.path.exists(candidate):
                            for d in os.listdir(candidate):
                                full = os.path.join(candidate, d)
                                if os.path.isdir(full) and os.path.exists(os.path.join(full, "nt_qq")):
                                    if qq_number and d == qq_number:
                                        self.log(f"从安装路径推断数据目录: {full}")
                                        return full
                                    elif not qq_number and (d.isdigit() or (len(d) >= 5 and d[0].isdigit())):
                                        self.log(f"从安装路径推断数据目录: {full}")
                                        return full
        except:
            pass

        # === 方法2：全盘扫描 ===
        drives = self._get_all_drives()
        username = os.environ.get('USERNAME', '')
        
        found_dirs = []  # 仅在未指定QQ号时收集候选
        for letter in drives:
            # 搜索根目录下的常见数据目录名
            for folder_name in ["QQ数据", "Tencent Files"]:
                base = f"{letter}:\\{folder_name}"
                if not os.path.exists(base):
                    continue
                for d in os.listdir(base):
                    full = os.path.join(base, d)
                    if not os.path.isdir(full):
                        continue
                    if not os.path.exists(os.path.join(full, "nt_qq")):
                        continue
                    if qq_number and d == qq_number:
                        self.log(f"找到QQ数据目录: {full}")
                        return full
                    elif not qq_number and (d.isdigit() or (len(d) >= 5 and d[0].isdigit())):
                        found_dirs.append(full)
            
            # 也搜索 Documents\Tencent Files
            if letter == 'C' and username:
                doc_path = f"C:\\Users\\{username}\\Documents\\Tencent Files"
                if os.path.exists(doc_path):
                    for d in os.listdir(doc_path):
                        full = os.path.join(doc_path, d)
                        if os.path.isdir(full) and os.path.exists(os.path.join(full, "nt_qq")):
                            if qq_number and d == qq_number:
                                self.log(f"找到QQ数据目录: {full}")
                                return full
                            elif not qq_number and (d.isdigit() or (len(d) >= 5 and d[0].isdigit())):
                                found_dirs.append(full)
        
        # 也搜索QQ安装目录的上级
        if self.qq_install_dir:
            parent = os.path.dirname(self.qq_install_dir)
            for folder_name in ["QQ数据", "Tencent Files"]:
                base = os.path.join(parent, folder_name)
                if not os.path.exists(base):
                    continue
                for d in os.listdir(base):
                    full = os.path.join(base, d)
                    if os.path.isdir(full) and os.path.exists(os.path.join(full, "nt_qq")):
                        if qq_number and d == qq_number:
                            self.log(f"找到QQ数据目录: {full}")
                            return full
                        elif not qq_number and (d.isdigit() or (len(d) >= 5 and d[0].isdigit())):
                            found_dirs.append(full)
        
        # 如果指定了QQ号但没找到，返回None（不随便返回别人的目录）
        if qq_number:
            self.log(f"未找到QQ号 {qq_number} 对应的数据目录")
            return None
        
        # 未指定QQ号时，返回找到的第一个候选
        if found_dirs:
            for d in found_dirs:
                dirname = os.path.basename(d)
                if dirname.isdigit():
                    self.log(f"找到QQ数据目录: {d}")
                    return d
            self.log(f"找到QQ数据目录: {found_dirs[0]}")
            return found_dirs[0]
        
        return None
    
    def find_databases(self, qq_data_dir):
        """在QQ数据目录中查找所有nt_msg.db文件"""
        db_files = []
        
        # 常见数据库路径
        common_db_paths = [
            os.path.join(qq_data_dir, "nt_qq", "nt_db", "nt_msg.db"),
            os.path.join(qq_data_dir, "nt_qq", "nt_db"),
        ]
        
        for db_path in common_db_paths:
            if os.path.isfile(db_path) and db_path.endswith('.db'):
                db_files.append(db_path)
            elif os.path.isdir(db_path):
                # 搜索目录下的所有.db文件
                for f in os.listdir(db_path):
                    if f.endswith('.db'):
                        full = os.path.join(db_path, f)
                        if os.path.isfile(full):
                            db_files.append(full)
        
        # 递归搜索nt_qq目录下的所有.db文件
        nt_qq_dir = os.path.join(qq_data_dir, "nt_qq")
        if os.path.exists(nt_qq_dir):
            for root, dirs, files in os.walk(nt_qq_dir):
                for f in files:
                    if f.endswith('.db') and 'msg' in f.lower():
                        full = os.path.join(root, f)
                        if full not in db_files:
                            db_files.append(full)
        
        # 去重
        db_files = list(dict.fromkeys(db_files))
        
        self.log(f"找到 {len(db_files)} 个数据库文件")
        for db in db_files:
            size_mb = os.path.getsize(db) / 1024 / 1024 if os.path.exists(db) else 0
            self.log(f"  📦 {os.path.basename(db)} ({size_mb:.1f}MB)")
        
        return db_files
    
    def find_wrapper_node(self):
        """查找wrapper.node路径"""
        if not self.qq_install_dir:
            return None
        
        # 搜索versions目录
        versions_dir = os.path.join(self.qq_install_dir, "versions")
        if os.path.exists(versions_dir):
            # 取最新版本
            versions = []
            for d in os.listdir(versions_dir):
                wrapper = os.path.join(versions_dir, d, "resources", "app", "wrapper.node")
                if os.path.exists(wrapper):
                    versions.append((d, wrapper))
            
            if versions:
                # 按版本号排序，取最新的
                versions.sort(key=lambda x: x[0], reverse=True)
                self.log(f"找到wrapper.node: {versions[0][1]}")
                return versions[0][1]
        return None
    
    def extract_key(self, wrapper_node_path=""):
        """提取QQ数据库密钥
        
        调试器法为主：先退出QQ→脚本以调试模式启动QQ→用户登录→自动截获密钥→关闭QQ
        备用：内存搜索法（从已运行的QQ进程内存中扫描）
        """
        if not wrapper_node_path:
            wrapper_node_path = self.find_wrapper_node()
        
        # === 主方式：调试器法（extract_key.ps1） ===
        # 这个方法最可靠：在 sqlite3_key_v2 被调用时从R8寄存器读取16位密钥
        if wrapper_node_path and os.path.exists(wrapper_node_path):
            # 查找extract_key.ps1：优先exe同级目录，其次PyInstaller打包目录
            if getattr(sys, 'frozen', False):
                # 先找exe旁边的（用户可能自己放了脚本文件）
                exe_dir = os.path.dirname(sys.executable)
                script_path = os.path.join(exe_dir, "extract_key.ps1")
                if not os.path.exists(script_path):
                    # 再找PyInstaller打包到内部的（--add-data打进来的）
                    script_path = os.path.join(sys._MEIPASS, "extract_key.ps1")
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                script_path = os.path.join(base_dir, "extract_key.ps1")
            if os.path.exists(script_path):
                self.log("🔧 使用调试器法提取密钥（最可靠）...")
                key = self._extract_key_debugger(wrapper_node_path, script_path)
                if key:
                    self.log(f"✅ 密钥提取成功: {key[:4]}{'*' * (len(key)-4)}", "success")
                    return key
                self.log("调试器法未找到密钥，尝试备用方式...", "warn")
            else:
                self.log("⚠️ extract_key.ps1 脚本不存在，跳过调试器法", "warn")
        else:
            if not wrapper_node_path:
                self.log("未找到wrapper.node路径，跳过调试器法", "warn")
        
        # === 备用方式：内存搜索法 ===
        self.log("🔍 尝试备用方式：从已运行的QQ进程内存中搜索密钥...")
        key = self._search_key_in_process()
        if key:
            self.log(f"✅ 密钥提取成功: {key[:4]}{'*' * (len(key)-4)}", "success")
            return key
        
        self.log("所有密钥提取方式均失败！", "error")
        return ""
    
    def _extract_key_debugger(self, wrapper_node_path, script_path):
        """调试器法提取密钥：退出QQ→脚本启动QQ+调试器→登录→截获密钥→关闭QQ
        
        核心流程：
        1. 检测QQ是否在运行，如果在运行则提示退出
        2. 以调试模式启动QQ（通过extract_key.ps1）
        3. 用户在QQ窗口登录
        4. QQ打开数据库时触发断点，脚本从R8寄存器读取16位ASCII密钥
        5. 截获成功后脚本自动关闭QQ进程
        6. 返回密钥
        
        注意：此方法会阻塞较长时间（等待用户登录），需要子线程运行
        """
        # 检测QQ是否正在运行，必须彻底关闭后才能用调试器法
        import time
        try:
            r = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq QQ.exe", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
            )
            if 'QQ.exe' in r.stdout:
                self.log("⚠️ 检测到QQ正在运行！调试器法需要QQ先退出。")
                self.log("正在自动关闭QQ进程...")
                try:
                    # 先正常关闭
                    subprocess.run(["taskkill", "/IM", "QQ.exe"], capture_output=True, timeout=5)
                    time.sleep(2)
                    # 检查是否还在运行
                    r2 = subprocess.run(
                        ["tasklist", "/FI", "IMAGENAME eq QQ.exe", "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
                    )
                    if 'QQ.exe' in r2.stdout:
                        self.log("QQ未响应正常关闭，强制结束...")
                        subprocess.run(["taskkill", "/IM", "QQ.exe", "/F"],
                                     capture_output=True, timeout=10)
                except Exception as e:
                    self.log(f"关闭QQ失败: {e}，请手动关闭QQ后重试", "error")
                    return ""
                
                # 等待QQ完全退出（包括后台进程）
                max_wait = 15  # 最多等15秒
                for wait_i in range(max_wait):
                    time.sleep(1)
                    r3 = subprocess.run(
                        ["tasklist", "/FI", "IMAGENAME eq QQ.exe", "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
                    )
                    if 'QQ.exe' not in r3.stdout:
                        break
                    if wait_i == max_wait - 1:
                        self.log("⚠️ QQ进程仍在运行，可能影响调试器启动", "warn")
                
                self.log("✅ QQ进程已关闭")
        except Exception:
            pass  # 检测失败不影响后续
        
        self.log("📋 流程说明：")
        self.log("  1. 脚本将以调试模式启动QQ")
        self.log("  2. 请在弹出的QQ窗口中登录你的账号")
        self.log("  3. 登录成功后脚本会自动截获密钥并关闭QQ")
        self.log(f"  wrapper.node: {wrapper_node_path}")
        self.log("")
        self.log("⏳ 正在启动QQ（调试模式），请登录...")
        
        try:
            # 使用subprocess.Popen运行extract_key.ps1
            # 隐藏PowerShell窗口
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # 方案：创建临时包装脚本，捕获所有输出
            # 问题：Write-Host输出不经过stdout，Popen捕获不到
            # 解决：用临时脚本包装，将Write-Host重写为Write-Output
            import tempfile
            wrapper_script = os.path.join(tempfile.gettempdir(), "qq_key_extract_wrapper.ps1")
            # 读取原始脚本，替换Write-Host为Write-Output
            with open(script_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            # 替换Write-Host为Write-Output（保留参数但去掉-ForegroundColor等仅显示参数）
            import re as _re
            modified = _re.sub(
                r'Write-Host\s+',
                'Write-Output ',
                original_content
            )
            # 去掉-ForegroundColor参数（Write-Output不支持）
            modified = _re.sub(
                r'\s+-ForegroundColor\s+\w+',
                '',
                modified
            )
            # 关键：去掉UTF-8自动重载机制！
            # 原脚本在PS5下会重新读取自身并执行一遍（第56-75行），
            # 导致整个脚本执行两次，QQ被启动两次，用户需要登录两次。
            # 我们的wrapper已经是UTF-8编码写入的，不需要重载。
            modified = _re.sub(
                r'#region\s+Reload\s+Script\s+as\s+UTF-8.*?#endregion',
                '',
                modified,
                flags=_re.DOTALL
            )
            with open(wrapper_script, 'w', encoding='utf-8-sig') as f:
                f.write(modified)
            
            cmd = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", wrapper_script,
                "-WrapperNodePath", wrapper_node_path
            ]
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,  # 行缓冲
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # 实时读取输出，最多等5分钟（用户登录可能慢）
            import time
            output_lines = []
            key = ""
            start_time = time.time()
            timeout = 300  # 5分钟超时
            key_found = False
            
            def _try_find_key_in_line(line):
                """从一行输出中尝试提取16位ASCII密钥（不依赖中文前缀）"""
                # 方法1：匹配常见前缀（中文可能乱码，所以也匹配纯结构）
                patterns = [
                    r'[：:]\s*["\']?([!-~]{16})["\']?',  # 冒号后16位可打印ASCII
                    r'Key\s*[：:]\s*["\']?([!-~]{16})["\']',  # Key: xxx
                ]
                for p in patterns:
                    m = re.search(p, line)
                    if m:
                        candidate = m.group(1)
                        # 排除明显不是密钥的（RVA、hex地址等）
                        if not any(x in candidate for x in ['0x', 'RVA', 'QQ', 'wrapper']):
                            return candidate
                return None
            
            while proc.poll() is None:
                if time.time() - start_time > timeout:
                    self.log("⏰ 等待超时（5分钟），终止QQ进程...", "warn")
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except:
                        proc.kill()
                    return ""
                
                try:
                    line = proc.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            output_lines.append(line)
                            # 只输出关键日志（过滤掉Verbose信息）
                            if any(kw in line for kw in ['找到', '密钥', '启动', '加载', '断点', '目标', '函数', 
                                                          '登录', '进程', '错误', '失败', 'RVA', 'wrapper',
                                                          '成功', '调试', '完成', 'Key', 'key',
                                                          '0x2', '0x3', 'LEA']):
                                self.log(f"  {line}")
                            
                            # 实时检测密钥——一旦发现就不再等待
                            if not key_found:
                                # 先尝试从带前缀的行提取
                                for pattern in [
                                    r'找到密钥[：:]\s*["\']?([^\s"\']+)["\']',
                                    r'加密密钥[：:]\s*["\']?([^\s"\']+)["\']',
                                    r'Key[：:]\s*["\']?([^\s"\']+)["\']',
                                    r'数据库密钥[：:]\s*["\']?([^\s"\']+)["\']',
                                ]:
                                    m = re.search(pattern, line, re.IGNORECASE)
                                    if m and len(m.group(1)) >= 16:
                                        key = m.group(1)
                                        key_found = True
                                        break
                                
                                # 前缀匹配失败（中文乱码），尝试结构化匹配
                                if not key_found:
                                    candidate = _try_find_key_in_line(line)
                                    if candidate:
                                        key = candidate
                                        key_found = True
                                
                                if key_found:
                                    self.log(f"✅ 密钥已捕获: {key[:4]}{'*' * (len(key)-4)}，正在清理QQ进程...", "success")
                                    # 立刻杀掉所有QQ进程（包括子进程）
                                    try:
                                        subprocess.run(["taskkill", "/IM", "QQ.exe", "/F"],
                                                     capture_output=True, timeout=10)
                                    except:
                                        pass
                except:
                    pass
            
            # 进程结束，读取剩余输出
            try:
                remaining = proc.stdout.read()
                if remaining:
                    output_lines.extend(remaining.strip().split('\n'))
            except:
                pass
            
            full_output = '\n'.join(output_lines)
            
            # 尝试多种格式匹配密钥
            # 注意：中文前缀可能因编码问题变成乱码，所以也要用不依赖中文的方式匹配
            patterns = [
                r'找到密钥[：:]\s*["\']?([^\s"\']+)["\']',
                r'加密密钥[：:]\s*["\']?([^\s"\']+)["\']',
                r'Key[：:]\s*["\']?([^\s"\']+)["\']',
                r'数据库密钥[：:]\s*["\']?([^\s"\']+)["\']',
            ]
            
            for pattern in patterns:
                key_match = re.search(pattern, full_output, re.IGNORECASE)
                if key_match:
                    key = key_match.group(1)
                    break
            
            # 如果中文前缀匹配失败（编码乱码），用结构化匹配
            if not key:
                # 查找输出中的16位可打印ASCII字符串（冒号后面通常是密钥值）
                # 输出格式可能是乱码前缀: >-DM8(ZEIHSKTXSQ 或直接在表格行中
                for line in output_lines:
                    candidate = _try_find_key_in_line(line)
                    if candidate:
                        key = candidate
                        break
            
            # 最后手段：在全部输出中搜索16位可打印ASCII（排除常见误匹配）
            if not key:
                all_16ascii = re.findall(r'[\x21-\x7E]{16}', full_output)
                for candidate in all_16ascii:
                    # 排除明显不是密钥的
                    if any(x in candidate for x in ['0x', 'RVA', 'QQ', 'wrapper', 'LEA', 'Function', 'Instruction']):
                        continue
                    # 密钥特征：16位可见ASCII，包含多种字符类型
                    has_upper = any(c.isupper() for c in candidate)
                    has_lower = any(c.islower() for c in candidate)
                    has_digit = any(c.isdigit() for c in candidate)
                    has_special = any(not c.isalnum() for c in candidate)
                    type_count = sum([has_upper, has_lower, has_digit, has_special])
                    if type_count >= 3:  # 至少3种字符类型（密钥通常包含大小写+数字+特殊字符）
                        key = candidate
                        break
            
            if key:
                # 密钥已提取成功，确保所有QQ进程都被杀掉
                # QQ NT是Chromium多进程架构，调试器只终止主进程，
                # 子进程（Renderer/GPU等）可能仍在运行并弹出登录窗口
                import time
                try:
                    subprocess.run(["taskkill", "/IM", "QQ.exe", "/F"],
                                 capture_output=True, timeout=10)
                    time.sleep(1)
                    # 再检查一次，确保彻底清理
                    r_check = subprocess.run(
                        ["tasklist", "/FI", "IMAGENAME eq QQ.exe", "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
                    )
                    if 'QQ.exe' in r_check.stdout:
                        subprocess.run(["taskkill", "/IM", "QQ.exe", "/F"],
                                     capture_output=True, timeout=10)
                        time.sleep(1)
                    self.log("✅ QQ进程已全部清理")
                except Exception:
                    pass
                return key
            
            self.log(f"调试器法未找到密钥。脚本输出:\n{full_output[:500]}", "warn")
            return ""
            
            self.log(f"调试器法未找到密钥。脚本输出:\n{full_output[:500]}", "warn")
            return ""
            
        except Exception as e:
            self.log(f"调试器法失败: {e}", "error")
            return ""
    
    def _search_key_in_process(self):
        """从已运行的QQ进程内存中搜索数据库密钥（静默收集+数据库验证）
        支持16位和32位密钥，分块读取避免卡死"""
        import ctypes
        import ctypes.wintypes
        import time
        
        # Windows API 常量
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        MEM_COMMIT = 0x1000
        PAGE_READWRITE = 0x04
        
        kernel32 = ctypes.windll.kernel32
        
        # 找到QQ进程（按内存占用排序，主进程通常最大）
        self.log("正在查找QQ进程...")
        
        try:
            # 获取QQ进程列表及内存占用
            r = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq QQ.exe", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, encoding='gbk', errors='replace', timeout=10
            )
            pid_mem = []  # [(pid, 内存KB), ...]
            for line in r.stdout.strip().split('\n'):
                if 'QQ.exe' in line:
                    parts = line.strip('"').split('","')
                    if len(parts) >= 5:
                        try:
                            pid = int(parts[1])
                            mem_str = parts[4].replace(',', '').replace(' K', '').replace('"', '').strip()
                            mem_kb = int(mem_str) if mem_str.isdigit() else 0
                            pid_mem.append((pid, mem_kb))
                        except (ValueError, IndexError):
                            pass
            
            if not pid_mem:
                self.log("未找到正在运行的QQ进程！", "warn")
                return ""
            
            # 按内存占用降序排列（主进程通常内存最大）
            pid_mem.sort(key=lambda x: x[1], reverse=True)
            pids = [p[0] for p in pid_mem]
            self.log(f"找到 {len(pids)} 个QQ进程（按内存排序，优先扫描主进程）")
            self.log(f"  主进程 PID={pid_mem[0][0]} ({pid_mem[0][1]//1024}MB)")
            if len(pid_mem) > 1:
                self.log(f"  其他进程: {', '.join(f'PID={p[0]}({p[1]//1024}MB)' for p in pid_mem[1:])}")
        except Exception as e:
            self.log(f"查找QQ进程失败: {e}", "warn")
            return ""
        
        # 先找主数据库文件路径（用于验证密钥）
        db_path_for_verify = None
        if hasattr(self, 'qq_data_dir') and self.qq_data_dir:
            nt_db_dir = os.path.join(self.qq_data_dir, "nt_qq", "nt_db")
            if os.path.exists(nt_db_dir):
                nt_msg_db = os.path.join(nt_db_dir, "nt_msg.db")
                if os.path.exists(nt_msg_db):
                    db_path_for_verify = nt_msg_db
                    self.log(f"找到验证数据库: nt_msg.db")
                else:
                    # 尝试其他db文件
                    for f in os.listdir(nt_db_dir):
                        if f.endswith('.db') and f != 'nt_msg.db':
                            db_path_for_verify = os.path.join(nt_db_dir, f)
                            self.log(f"使用验证数据库: {f}")
                            break
            else:
                self.log("未找到nt_db目录，将无法验证密钥", "warn")
        
        if not db_path_for_verify:
            self.log("⚠️ 无验证数据库，找到的候选密钥无法自动验证", "warn")
        
        # 准备数据库验证函数
        _verify_tmp_path = None
        def verify_key(key):
            """快速验证密钥是否能解密数据库"""
            nonlocal _verify_tmp_path
            if not db_path_for_verify:
                return False
            try:
                from sqlcipher3 import dbapi2 as sqlcipher
            except ImportError:
                try:
                    from pysqlcipher3 import dbapi2 as sqlcipher
                except ImportError:
                    return False
            import tempfile
            try:
                with open(db_path_for_verify, 'rb') as f:
                    data = f.read()
                sqlite_magic = b'SQLite format 3\x00'
                clean_data = data[1024:] if not data.startswith(sqlite_magic) and len(data) > 1024 else data
                tmp_path = os.path.join(tempfile.gettempdir(), "qq_key_verify.db")
                with open(tmp_path, 'wb') as f:
                    f.write(clean_data)
                _verify_tmp_path = tmp_path
                conn = sqlcipher.connect(tmp_path)
                cur = conn.cursor()
                cur.execute(f"PRAGMA key = '{key}'")
                cur.execute("PRAGMA cipher_page_size = 4096")
                cur.execute("PRAGMA kdf_iter = 4000")
                cur.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
                cur.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512")
                cur.execute("PRAGMA cipher = 'aes-256-cbc'")
                cur.execute("SELECT count(*) FROM sqlite_master")
                count = cur.fetchone()[0]
                conn.close()
                os.remove(tmp_path)
                _verify_tmp_path = None
                return count > 0
            except:
                try: conn.close()
                except: pass
                try: os.remove(tmp_path)
                except: pass
                _verify_tmp_path = None
                return False
        
        # 从QQ进程内存中搜索密钥
        # QQ的密钥可能是16位或32位可见ASCII字符
        found_keys = set()
        verified_key = ""  # 一旦验证成功就返回
        
        # 密钥长度范围：16位（如 >-DM8(ZEIHSKTXSQ）或 32位
        MIN_KEY_LEN = 16
        MAX_KEY_LEN = 32
        # 分块读取大小：4MB，避免一次性分配太大buffer
        CHUNK_SIZE = 4 * 1024 * 1024
        
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.wintypes.DWORD),
                ("Protect", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
            ]
        
        for pid_idx, pid in enumerate(pids):
            if verified_key:
                break  # 已经找到密钥，不用扫其他进程了
            
            process_label = "主进程" if pid_idx == 0 else f"子进程{pid_idx}"
            self.log(f"正在扫描{process_label} PID={pid}...")
            
            hProcess = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
            )
            if not hProcess:
                self.log(f"  无法打开进程 PID={pid}（需要管理员权限）", "warn")
                continue
            
            try:
                address = 0
                max_addr = 0x7FFFFFFFFFFF
                region_count = 0
                scanned_mb = 0
                batch_keys = []  # 批量收集，定期验证
                last_log_time = time.time()
                
                mbi = MEMORY_BASIC_INFORMATION()
                mbi_size = ctypes.sizeof(mbi)
                
                while address < max_addr:
                    if verified_key:
                        break
                    
                    result = kernel32.VirtualQueryEx(
                        hProcess, ctypes.c_void_p(address),
                        ctypes.byref(mbi), mbi_size
                    )
                    
                    if result == 0:
                        break
                    
                    # 只扫描已提交的 PAGE_READWRITE 堆内存
                    # 密钥一定在堆上（程序运行时分配的），不需要扫代码段或执行段
                    if (mbi.State == MEM_COMMIT and 
                        mbi.Protect == PAGE_READWRITE):
                        
                        region_size = mbi.RegionSize
                        # 跳过超大区域（>64MB的通常是映射文件）
                        if region_size > 64 * 1024 * 1024:
                            address += region_size
                            continue
                        
                        # 分块读取，避免一次性分配太大内存
                        offset_in_region = 0
                        while offset_in_region < region_size:
                            if verified_key:
                                break
                            
                            read_size = min(CHUNK_SIZE, region_size - offset_in_region)
                            read_addr = mbi.BaseAddress + offset_in_region
                            
                            try:
                                buffer = (ctypes.c_ubyte * read_size)()
                                bytes_read = ctypes.c_size_t()
                                
                                if kernel32.ReadProcessMemory(
                                    hProcess, ctypes.c_void_p(read_addr),
                                    buffer, read_size, ctypes.byref(bytes_read)
                                ):
                                    data = bytes(buffer[:bytes_read.value])
                                    scanned_mb += len(data) / 1024 / 1024
                                    
                                    # 定期输出进度（每2秒）
                                    now = time.time()
                                    if now - last_log_time >= 2:
                                        self.log(f"  已扫描 {scanned_mb:.0f}MB, 候选 {len(found_keys)} 个...")
                                        last_log_time = now
                                    
                                    # 搜索16-32字节连续可见ASCII字符
                                    i = 0
                                    while i < len(data) - MIN_KEY_LEN:
                                        if (0x21 <= data[i] <= 0x7E and
                                            0x21 <= data[i+1] <= 0x7E and
                                            0x21 <= data[i+2] <= 0x7E and
                                            0x21 <= data[i+3] <= 0x7E):
                                            end = i + 4
                                            while end < len(data) and 0x21 <= data[end] <= 0x7E:
                                                end += 1
                                            
                                            length = end - i
                                            # 检查是否在有效长度范围内
                                            if MIN_KEY_LEN <= length <= MAX_KEY_LEN:
                                                candidate = data[i:i+length]
                                                try:
                                                    key_str = candidate.decode('ascii')
                                                    has_lower = any(c.islower() for c in key_str)
                                                    has_upper = any(c.isupper() for c in key_str)
                                                    has_digit = any(c.isdigit() for c in key_str)
                                                    has_special = any(not c.isalnum() for c in key_str)
                                                    char_types = sum([has_lower, has_upper, has_digit, has_special])
                                                    
                                                    if (char_types >= 2 and 
                                                        not key_str.isalpha() and 
                                                        not key_str.isdigit() and
                                                        '/' not in key_str and
                                                        '\\' not in key_str and
                                                        ':' not in key_str and
                                                        not key_str.startswith('http') and
                                                        '.dll' not in key_str and
                                                        '.exe' not in key_str and
                                                        '.sys' not in key_str and
                                                        '.com' not in key_str and
                                                        'SELECT' not in key_str and
                                                        'INSERT' not in key_str and
                                                        'sqlite' not in key_str and
                                                        'CREATE' not in key_str and
                                                        'UPDATE' not in key_str and
                                                        'DELETE' not in key_str and
                                                        'rogram' not in key_str and
                                                        'indow' not in key_str and
                                                        'icroso' not in key_str and
                                                        'ontent' not in key_str and
                                                        'ersist' not in key_str and
                                                        'haract' not in key_str and
                                                        'nviron' not in key_str and
                                                        'ath' not in key_str):
                                                        
                                                        if key_str not in found_keys:
                                                            found_keys.add(key_str)
                                                            batch_keys.append(key_str)
                                                            
                                                            # 每收集3个候选就验证一次（快速返回）
                                                            if len(batch_keys) >= 3 and db_path_for_verify:
                                                                for bk in batch_keys:
                                                                    if verify_key(bk):
                                                                        verified_key = bk
                                                                        break
                                                                if verified_key:
                                                                    break
                                                                batch_keys = []
                                                except:
                                                    pass
                                            i = end
                                        else:
                                            i += 1
                            except:
                                pass
                            
                            offset_in_region += read_size
                    
                    address += mbi.RegionSize
                    region_count += 1
                
                self.log(f"  {process_label}扫描完成: {scanned_mb:.0f}MB, 累计候选 {len(found_keys)} 个")
                
                # 扫完一个进程后，如果还没验证过，验证所有候选
                if not verified_key and batch_keys and db_path_for_verify:
                    self.log(f"  正在验证 {len(batch_keys)} 个候选密钥...")
                    for bk in batch_keys:
                        if verify_key(bk):
                            verified_key = bk
                            break
                    batch_keys = []
                
            finally:
                kernel32.CloseHandle(hProcess)
        
        # 如果通过验证找到了密钥
        if verified_key:
            self.log(f"✅ 密钥验证成功: {verified_key[:4]}{'*' * (len(verified_key)-4)}", "success")
            return verified_key
        
        # 没有数据库验证条件，或验证全部失败——返回最可能的候选
        if found_keys:
            if db_path_for_verify:
                self.log("数据库验证未通过，可能是密钥和数据库不是同一次QQ登录", "warn")
            
            scored = []
            for key in found_keys:
                special_count = sum(1 for c in key if not c.isalnum())
                type_count = sum([
                    any(c.islower() for c in key),
                    any(c.isupper() for c in key),
                    any(c.isdigit() for c in key),
                    any(not c.isalnum() for c in key)
                ])
                # 16位密钥得分加成（之前用extract_key.ps1提取的是16位）
                len_bonus = 3 if len(key) == 16 else 0
                scored.append((key, special_count * 2 + type_count + len_bonus))
            
            scored.sort(key=lambda x: x[1], reverse=True)
            best_key = scored[0][0]
            self.log(f"从 {len(found_keys)} 个候选中选出最可能的密钥: {best_key[:4]}{'*' * (len(best_key)-4)}")
            return best_key
        
        self.log("未在QQ进程内存中找到候选密钥", "warn")
        return ""
    
    def decrypt_database(self, db_path, key):
        """解密QQ NT数据库（支持多种解密方式）"""
        if not os.path.exists(db_path):
            self.log(f"数据库文件不存在: {db_path}", "error")
            return None
        
        # 检查文件大小
        file_size = os.path.getsize(db_path)
        self.log(f"数据库大小: {file_size/1024/1024:.1f}MB")
        
        if file_size < 1024:
            self.log("数据库文件太小，可能已损坏或为空", "error")
            return None
        
        # 读取数据库数据
        with open(db_path, 'rb') as f:
            data = f.read()
        
        # 检测是否有NTQQ自定义头（1024字节）
        # SQLite魔数是 "SQLite format 3\x00"
        sqlite_magic = b'SQLite format 3\x00'
        has_custom_header = not data.startswith(sqlite_magic)
        
        if has_custom_header:
            self.log("检测到NTQQ自定义头，正在移除...")
            clean_data = data[1024:] if len(data) > 1024 else data
        else:
            self.log("数据库没有自定义头（可能已解密）")
            clean_data = data
        
        # 保存清理后的数据
        clean_path = db_path + ".clean.db"
        with open(clean_path, 'wb') as f:
            f.write(clean_data)
        self.clean_db_path = clean_path
        
        # === 尝试方式1: sqlcipher3 Python模块 ===
        sqlcipher_module = self._import_sqlcipher()
        if sqlcipher_module:
            self.log("使用 sqlcipher3 模块解密...")
            return self._decrypt_with_sqlcipher(clean_path, key, sqlcipher_module)
        
        # === 尝试方式2: sqlcipher.exe 命令行工具 ===
        sqlcipher_exe = self._find_sqlcipher_exe()
        if sqlcipher_exe:
            self.log("使用 sqlcipher.exe 命令行工具解密...")
            return self._decrypt_with_sqlcipher_cli(clean_path, key, sqlcipher_exe)
        
        # === 所有方式都失败，尝试自动安装 ===
        self.log("正在尝试自动安装 sqlcipher3-wheels...", "warn")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "sqlcipher3-wheels"],
                         capture_output=True, timeout=120)
            sqlcipher_module = self._import_sqlcipher()
            if sqlcipher_module:
                self.log("✅ sqlcipher3-wheels 安装成功！", "success")
                return self._decrypt_with_sqlcipher(clean_path, key, sqlcipher_module)
        except Exception as e:
            self.log(f"自动安装失败: {e}", "warn")
        
        # === 彻底失败 ===
        self.log("❌ 无法解密数据库！缺少 sqlcipher3 解密模块。", "error")
        self.log("请手动安装: pip install sqlcipher3-wheels", "error")
        return None
    
    def _import_sqlcipher(self):
        """尝试导入sqlcipher3模块"""
        try:
            from sqlcipher3 import dbapi2 as sqlcipher
            return sqlcipher
        except ImportError:
            pass
        try:
            from pysqlcipher3 import dbapi2 as sqlcipher
            return sqlcipher
        except ImportError:
            pass
        return None
    
    def _decrypt_with_sqlcipher(self, clean_path, key, sqlcipher):
        """使用Python sqlcipher模块解密"""
        self.log("正在解密数据库...")
        conn = sqlcipher.connect(clean_path)
        cur = conn.cursor()
        
        # 设置解密参数（QQ NT的SQLCipher参数）
        cur.execute(f"PRAGMA key = '{key}'")
        cur.execute("PRAGMA cipher_page_size = 4096")
        cur.execute("PRAGMA kdf_iter = 4000")
        cur.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
        cur.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512")
        cur.execute("PRAGMA cipher = 'aes-256-cbc'")
        
        # 验证解密是否成功
        try:
            cur.execute("SELECT count(*) FROM sqlite_master")
            count = cur.fetchone()[0]
            self.log(f"✅ 数据库解密成功！共 {count} 个表", "success")
            
            # 列出所有表
            tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_names = [t[0] for t in tables]
            self.log(f"数据库表: {', '.join(table_names[:20])}")
            
            return conn
        except Exception as e:
            self.log(f"❌ 数据库解密失败: {e}", "error")
            self.log("可能原因：密钥错误、QQ版本不匹配、或数据库已损坏", "error")
            conn.close()
            if os.path.exists(clean_path):
                os.remove(clean_path)
            return None
    
    def _find_sqlcipher_exe(self):
        """查找sqlcipher.exe命令行工具"""
        # PyInstaller打包后：优先exe同级目录，其次打包内部目录
        if getattr(sys, 'frozen', False):
            local_exe = os.path.join(os.path.dirname(sys.executable), "sqlcipher.exe")
            if not os.path.exists(local_exe):
                local_exe = os.path.join(sys._MEIPASS, "sqlcipher.exe")
        else:
            local_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sqlcipher.exe")
        if os.path.exists(local_exe):
            return local_exe
        
        # 2. PATH中查找
        try:
            result = subprocess.run(["where", "sqlcipher"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')[0].strip()
        except:
            pass
        
        return None
    
    def _decrypt_with_sqlcipher_cli(self, clean_path, key, sqlcipher_exe):
        """使用sqlcipher命令行工具解密数据库到明文SQLite"""
        self.log("正在用sqlcipher.exe解密数据库...")
        
        # 生成解密后的明文数据库路径
        decrypted_path = clean_path.replace('.clean.db', '.decrypted.db')
        
        # 构建SQL命令
        sql_cmds = f"""
PRAGMA key = '{key}';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;
PRAGMA cipher = 'aes-256-cbc';
ATTACH DATABASE '{decrypted_path}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""
        
        # 执行命令
        try:
            result = subprocess.run(
                [sqlcipher_exe, clean_path],
                input=sql_cmds,
                capture_output=True,
                text=True,
                timeout=120,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode != 0:
                self.log(f"sqlcipher.exe 执行失败: {result.stderr[:300]}", "error")
                return None
            
            if not os.path.exists(decrypted_path):
                self.log("解密后数据库文件未生成", "error")
                return None
            
            # 用普通sqlite3打开解密后的数据库
            import sqlite3
            conn = sqlite3.connect(decrypted_path)
            cur = conn.cursor()
            
            cur.execute("SELECT count(*) FROM sqlite_master")
            count = cur.fetchone()[0]
            self.log(f"✅ 数据库解密成功！共 {count} 个表", "success")
            
            tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_names = [t[0] for t in tables]
            self.log(f"数据库表: {', '.join(table_names[:20])}")
            
            return conn
            
        except subprocess.TimeoutExpired:
            self.log("sqlcipher.exe 执行超时", "error")
            return None
        except Exception as e:
            self.log(f"sqlcipher.exe 执行失败: {e}", "error")
            return None
    
    def _load_contact_remarks(self, conn):
        """从数据库加载联系人备注映射和群名映射
        
        Returns:
            tuple: (qq_remarks, group_names)
            qq_remarks: dict {QQ号: 备注名}  — 备注优先，没有则用昵称
            group_names: dict {群号: 群名}
        """
        qq_remarks = {}
        group_names = {}
        cur = conn.cursor()
        
        # 1. 从 recent_contact_v3_table 读取私聊联系人备注
        try:
            tables = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            
            if 'recent_contact_v3_table' in tables:
                # 41135=备注名, 40093=QQ昵称, 40030=QQ号
                rows = cur.execute(
                    "SELECT [40030], [41135], [40093] FROM recent_contact_v3_table WHERE [40010]=1"
                ).fetchall()
                
                for uin, remark, nick in rows:
                    if not uin:
                        continue
                    uin_str = str(uin)
                    # 优先用备注(41135)，没有备注用昵称(40093)
                    name = (remark or nick or "").strip()
                    if name:
                        qq_remarks[uin_str] = name
                self.log(f"从联系人表加载了 {len(qq_remarks)} 个联系人名称", "success")
        except Exception as e:
            self.log(f"读取联系人备注失败: {e}", "warn")
        
        # 2. 从 profile_info.db 读取好友备注（buddy_list的1002列）
        try:
            if self.qq_data_dir:
                profile_db_path = os.path.join(self.qq_data_dir, "nt_qq", "nt_db", "profile_info.db")
                if os.path.exists(profile_db_path):
                    self.log("正在解密 profile_info.db 加载好友备注...")
                    profile_conn = self._open_aux_db(profile_db_path)
                    if not profile_conn:
                        self.log("profile_info.db 解密跳过（无需关注）", "info")
                    if profile_conn:
                        try:
                            p_cur = profile_conn.cursor()
                            # 直接从buddy_list的1002列读备注，用1001列(QQ号)匹配
                            target_uins = ['1692804423', '2524024851', '2575428163', '3577921378', '1343042672']
                            for uin in target_uins:
                                row = p_cur.execute("SELECT [1000], [1002] FROM [buddy_list] WHERE [1001]=?", (uin,)).fetchone()
                                if row:
                                    self.log(f"[调试] profile_info.buddy_list UIN={uin}: uid={row[0]} remark={repr(row[1])}", "info")
                        finally:
                            profile_conn.close()
        except Exception as e:
            self.log(f"读取profile_info.db失败: {e}", "warn")

        # 3. 从 group_info.db 读取群名
        try:
            if not self.qq_data_dir:
                self.log("未设置数据目录，跳过群名加载", "warn")
            else:
                group_db_path = os.path.join(self.qq_data_dir, "nt_qq", "nt_db", "group_info.db")
                if os.path.exists(group_db_path):
                    self.log("正在解密 group_info.db 加载群名...")
                    group_conn = self._open_aux_db(group_db_path)
                    if not group_conn:
                        self.log("group_info.db 解密跳过（无需关注）", "info")
                    if group_conn:
                        try:
                            g_cur = group_conn.cursor()
                            g_tables = [t[0] for t in g_cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                            if 'group_list' in g_tables:
                                g_rows = g_cur.execute("SELECT [60001], [60007] FROM group_list").fetchall()
                                for gid, gname in g_rows:
                                    if gid and gname:
                                        group_names[str(gid)] = str(gname).strip()
                                self.log(f"从群信息表加载了 {len(group_names)} 个群名", "success")
                        finally:
                            group_conn.close()
        except Exception as e:
            self.log(f"读取群名失败: {e}", "warn")
        
        return qq_remarks, group_names
    
    def _open_aux_db(self, db_path):
        """解密并打开辅助数据库（如 group_info.db）"""
        sqlcipher_module = self._import_sqlcipher()
        if not sqlcipher_module:
            return None

        file_size = os.path.getsize(db_path)
        if file_size < 1024:
            return None

        with open(db_path, 'rb') as f:
            data = f.read()

        sqlite_magic = b'SQLite format 3\x00'
        has_custom_header = not data.startswith(sqlite_magic) and len(data) > 1024
        clean_data = data[1024:] if has_custom_header else data

        clean_path = db_path + ".clean.db"
        conn = None
        try:
            with open(clean_path, 'wb') as f:
                f.write(clean_data)

            conn = sqlcipher_module.connect(clean_path)
            cur = conn.cursor()

            if has_custom_header:
                # 有自定义头，需要解密
                cur.execute(f"PRAGMA key = '{self.key}'")
                cur.execute("PRAGMA cipher_page_size = 4096")
                cur.execute("PRAGMA kdf_iter = 4000")
                cur.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
                cur.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512")
                cur.execute("PRAGMA cipher = 'aes-256-cbc'")
            else:
                # 没有自定义头，可能已解密或本身就是明文
                cur.execute("PRAGMA key = ''")

            # 验证解密（带超时保护）
            try:
                cur.execute("SELECT count(*) FROM sqlite_master LIMIT 1")
            except Exception:
                # 明文数据库用空密钥打不开，尝试用主密钥
                if not has_custom_header:
                    conn.close()
                    conn = sqlcipher_module.connect(clean_path)
                    cur = conn.cursor()
                    cur.execute(f"PRAGMA key = '{self.key}'")
                    cur.execute("PRAGMA cipher_page_size = 4096")
                    cur.execute("PRAGMA kdf_iter = 4000")
                    cur.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
                    cur.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512")
                    cur.execute("PRAGMA cipher = 'aes-256-cbc'")
                    cur.execute("SELECT count(*) FROM sqlite_master LIMIT 1")

            return conn
        except Exception:
            try:
                if conn:
                    conn.close()
            except:
                pass
            return None
    
    def scan_chats(self, conn, my_qq=""):
        """扫描所有聊天，返回列表"""
        self.my_qq = my_qq
        cur = conn.cursor()
        chat_list = []

        # 先检查有哪些表
        tables = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.log(f"数据库包含的表: {', '.join(tables)}")
        
        # 加载联系人备注和群名映射
        self.log("正在加载联系人备注...")
        qq_remarks, group_names = self._load_contact_remarks(conn)
        self._qq_remarks = qq_remarks  # 保存供导出使用
        self._group_names = group_names
        self.log(f"联系人映射共 {len(qq_remarks)} 个, 群名映射共 {len(group_names)} 个")
        
        # 扫描私聊
        c2c_chats = {}
        if 'c2c_msg_table' in tables:
            try:
                # 先获取列信息
                cols_info = cur.execute("PRAGMA table_info(c2c_msg_table)").fetchall()
                cols = [c[1] for c in cols_info]
                self.log(f"私聊表列: {', '.join(cols[:15])}...")
                
                rows = cur.execute("SELECT * FROM c2c_msg_table ORDER BY [40050] ASC").fetchall()
                self.log(f"私聊表共 {len(rows)} 条原始记录，正在解析...")
                total_rows = len(rows)
                batch_size = max(1000, total_rows // 20)  # 每5%报一次进度
                for idx, row in enumerate(rows):
                    if idx > 0 and idx % batch_size == 0:
                        pct = idx * 100 // total_rows
                        self.signals.progress.emit(pct, 100)
                        self.log(f"  私聊解析进度: {pct}% ({idx}/{total_rows})")
                
                for row in rows:
                    col_map = dict(zip(cols, row))
                    peer_uin = str(col_map.get(FIELD_PEER_UIN, ''))
                    sender_uin = str(col_map.get(FIELD_SENDER_UIN, ''))
                    ts = col_map.get(FIELD_TIMESTAMP, 0)
                    body = col_map.get(FIELD_BODY, b'')
                    sender_name = str(col_map.get(FIELD_SENDER_NAME, ''))
                    
                    # 跳过无效的聊天对象（系统消息如QQ0的红包通知）
                    if not peer_uin or peer_uin == '0':
                        continue
                    
                    text = decode_protobuf_text(body)
                    if not is_valid_chat_message(text):
                        continue
                    
                    if peer_uin not in c2c_chats:
                        is_me = sender_uin == my_qq
                        # 优先用备注名，其次用消息中的sender_name，最后用QQ号
                        remark_name = qq_remarks.get(peer_uin, "")
                        if remark_name and not is_me:
                            display_name = remark_name
                        elif sender_name and not is_me:
                            display_name = sender_name
                        else:
                            display_name = remark_name or f'QQ{peer_uin}'
                        c2c_chats[peer_uin] = {
                            'peer_uin': peer_uin,
                            'display_name': display_name,
                            'msg_count': 0,
                            'is_group': False,
                            'messages': [],
                            'sender_names': defaultdict(int),  # 统计发送者名字
                        }
                    c2c_chats[peer_uin]['msg_count'] += 1
                    c2c_chats[peer_uin]['messages'].append({
                        'sender_uin': sender_uin,
                        'peer_uin': peer_uin,
                        'timestamp': ts,
                        'body': body,
                        'sender_name': sender_name,
                        'text': text,
                        'is_me': sender_uin == my_qq,
                        'chat_type': 'private',
                    })
                    # 统计非我的发送者名字（用于获取更准确的昵称）
                    if sender_uin != my_qq and sender_name:
                        c2c_chats[peer_uin]['sender_names'][sender_name] += 1
                
                # 更新显示名：备注名优先，其次用消息中的名字
                for uin, chat in c2c_chats.items():
                    remark = qq_remarks.get(uin, "")
                    if remark:
                        chat['display_name'] = remark
                    elif chat['sender_names']:
                        best_name = max(chat['sender_names'], key=chat['sender_names'].get)
                        if best_name:
                            chat['display_name'] = best_name
                    del chat['sender_names']  # 不需要传递给前端
                
            except Exception as e:
                self.log(f"私聊扫描出错: {e}", "warn")
        else:
            self.log("未找到私聊表(c2c_msg_table)", "warn")
        
        # 扫描群聊
        group_chats = {}
        if 'group_msg_table' in tables:
            try:
                cols_info = cur.execute("PRAGMA table_info(group_msg_table)").fetchall()
                cols = [c[1] for c in cols_info]
                
                rows = cur.execute("SELECT * FROM group_msg_table ORDER BY [40050] ASC").fetchall()
                self.log(f"群聊表共 {len(rows)} 条原始记录，正在解析...")
                total_rows = len(rows)
                batch_size = max(1000, total_rows // 20)
                for idx, row in enumerate(rows):
                    if idx > 0 and idx % batch_size == 0:
                        pct = idx * 100 // total_rows
                        self.signals.progress.emit(pct, 100)
                        self.log(f"  群聊解析进度: {pct}% ({idx}/{total_rows})")
                
                for row in rows:
                    col_map = dict(zip(cols, row))
                    peer_uin = str(col_map.get(FIELD_PEER_UIN, ''))  # 群号
                    sender_uin = str(col_map.get(FIELD_SENDER_UIN, ''))
                    ts = col_map.get(FIELD_TIMESTAMP, 0)
                    body = col_map.get(FIELD_BODY, b'')
                    sender_name = str(col_map.get(FIELD_SENDER_NAME, ''))
                    
                    # 跳过无效的群号
                    if not peer_uin or peer_uin == '0':
                        continue
                    
                    text = decode_protobuf_text(body)
                    if not is_valid_chat_message(text):
                        continue
                    
                    if peer_uin not in group_chats:
                        group_chats[peer_uin] = {
                            'peer_uin': peer_uin,
                            'display_name': f'群{peer_uin}',
                            'msg_count': 0,
                            'is_group': True,
                            'messages': [],
                            'group_names': defaultdict(int),
                        }
                    group_chats[peer_uin]['msg_count'] += 1
                    group_chats[peer_uin]['messages'].append({
                        'sender_uin': sender_uin,
                        'peer_uin': peer_uin,
                        'timestamp': ts,
                        'body': body,
                        'sender_name': sender_name,
                        'text': text,
                        'is_me': sender_uin == my_qq,
                        'chat_type': 'group',
                    })
                    if sender_name:
                        group_chats[peer_uin]['group_names'][sender_name] += 1
                
                # 用群名替换默认名
                for uin, chat in group_chats.items():
                    gname = group_names.get(uin, "")
                    if gname:
                        chat['display_name'] = gname
                    del chat['group_names']
                
            except Exception as e:
                self.log(f"群聊扫描出错: {e}", "warn")
        else:
            self.log("未找到群聊表(group_msg_table)", "warn")
        
        # 合并
        all_chats = list(c2c_chats.values()) + list(group_chats.values())
        
        # 按名字去重：相同display_name只保留消息最多的那个
        name_best = {}
        for chat in all_chats:
            name = chat.get('display_name', f"QQ{chat['peer_uin']}")
            if name not in name_best or chat['msg_count'] > name_best[name]['msg_count']:
                name_best[name] = chat
        all_chats = list(name_best.values())
        
        all_chats.sort(key=lambda x: x['msg_count'], reverse=True)
        
        private_count = len(c2c_chats)
        group_count = len(group_chats)
        total_msgs = sum(c['msg_count'] for c in all_chats)
        self.log(f"扫描完成: {private_count} 个私聊, {group_count} 个群聊, 共 {total_msgs} 条消息", "success")
        return all_chats
    
    def export_chats(self, selected_chats, export_format="html"):
        """导出选中的聊天"""
        os.makedirs(self.chat_export_dir, exist_ok=True)
        total = len(selected_chats)
        
        for i, chat in enumerate(selected_chats):
            self.signals.progress.emit(i + 1, total)
            peer_uin = chat['peer_uin']
            display_name = chat['display_name']
            messages = chat['messages']
            chat_type = chat.get('is_group', False) and 'group' or 'private'
            
            safe_name = "".join(c if c.isalnum() or c in '_-' else '_' for c in display_name)
            # 避免文件名冲突
            safe_name = f"{safe_name}_{peer_uin}" if peer_uin else safe_name
            
            if "html" in export_format:
                html_dir = os.path.join(self.chat_export_dir, "html")
                os.makedirs(html_dir, exist_ok=True)
                html_path = os.path.join(html_dir, f"{safe_name}.html")
                self._export_html(display_name, messages, html_path, chat_type)
            
            if "txt" in export_format:
                txt_dir = os.path.join(self.chat_export_dir, "txt")
                os.makedirs(txt_dir, exist_ok=True)
                txt_path = os.path.join(txt_dir, f"{safe_name}.txt")
                self._export_txt(display_name, messages, txt_path, chat_type)
            
            if "json" in export_format:
                json_dir = os.path.join(self.chat_export_dir, "json")
                os.makedirs(json_dir, exist_ok=True)
                json_path = os.path.join(json_dir, f"{safe_name}.json")
                self._export_json(display_name, messages, json_path, chat_type)
        
        self.log(f"✅ 导出完成！共 {total} 个聊天 → {self.chat_export_dir}", "success")
    
    def _export_html(self, display_name, messages, out_path, chat_type='private'):
        """导出为QQ风格HTML
        
        Args:
            display_name: 聊天对象名称（私聊=备注名, 群聊=群名）
            messages: 消息列表
            out_path: 输出路径
            chat_type: 'private' 或 'group'
        """
        import html as html_mod
        
        parts = []
        last_date = ''
        
        for msg in messages:
            ts = msg.get('timestamp', 0)
            if not ts:
                continue
            
            try:
                dt = datetime.fromtimestamp(ts)
            except:
                continue
            
            date_str = dt.strftime('%Y年%m月%d日')
            date_id = dt.strftime('%Y-%m-%d')
            time_str = dt.strftime('%H:%M')
            
            if date_str != last_date:
                parts.append(f'<div class="date-sep" id="date-{date_id}"><span>{date_str}</span></div>')
                last_date = date_str
            
            is_me = msg.get('is_me', False)
            if chat_type == 'group':
                # 群聊：保留各人的sender_name
                if is_me:
                    sender_name = '我'
                else:
                    sender_name = msg.get('sender_name', '') or f'QQ{msg.get("sender_uin", "")}'
                sender_name = html_mod.escape(sender_name)
            else:
                # 私聊：对方用备注名
                sender_name = '我' if is_me else html_mod.escape(display_name)
            content = html_mod.escape(msg.get('text', '')).replace('\n', '<br>')
            
            if is_me:
                parts.append(f'''
                <div class="msg-row me">
                    <div class="avatar avatar-me">我</div>
                    <div class="msg-body">
                        <div class="msg-meta right">我 {time_str}</div>
                        <div class="bubble me-bubble">{content}</div>
                    </div>
                </div>''')
            else:
                parts.append(f'''
                <div class="msg-row other">
                    <div class="avatar avatar-other">{html_mod.escape(sender_name[0] if sender_name else "?")}</div>
                    <div class="msg-body">
                        <div class="msg-meta">{sender_name} {time_str}</div>
                        <div class="bubble other-bubble">{content}</div>
                    </div>
                </div>''')
        
        # 日期选项
        date_set = []
        seen_dates = set()
        for msg in messages:
            ts = msg.get('timestamp', 0)
            if ts:
                try:
                    ds = datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
                    if ds not in seen_dates:
                        seen_dates.add(ds)
                        date_set.append(ds)
                except:
                    pass
        date_options = ''.join(f'<option value="{d}">{d}</option>' for d in date_set)
        
        type_label = "群聊" if any(m.get('is_group') for m in messages) else "私聊"
        
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QQ聊天记录 - {html_mod.escape(display_name)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; background: #f5f5f5; color: #333; }}
.header {{ background: #12b7f3; color: white; padding: 16px 20px; position: sticky; top: 0; z-index: 10; }}
.header h1 {{ font-size: 17px; font-weight: 500; }}
.header .info {{ font-size: 12px; color: rgba(255,255,255,0.85); margin-top: 4px; }}
.toolbar {{ display: flex; align-items: center; gap: 10px; margin-top: 8px; }}
.toolbar label {{ font-size: 12px; color: rgba(255,255,255,0.8); }}
.toolbar select {{ border: 1px solid rgba(255,255,255,0.3); border-radius: 4px; padding: 4px 8px; font-size: 12px; background: rgba(255,255,255,0.2); color: white; cursor: pointer; }}
.toolbar select option {{ background: #333; color: white; }}
.chat-container {{ max-width: 800px; margin: 0 auto; padding: 16px 20px; }}
.date-sep {{ text-align: center; margin: 20px 0 12px; }}
.date-sep span {{ background: #dadada; color: #666; padding: 4px 12px; border-radius: 4px; font-size: 12px; }}
.msg-row {{ display: flex; margin-bottom: 16px; align-items: flex-start; }}
.msg-row.me {{ flex-direction: row-reverse; }}
.avatar {{ flex-shrink: 0; width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; color: white; margin-top: 18px; }}
.avatar-me {{ background: #12b7f3; }}
.avatar-other {{ background: #ff9800; }}
.msg-body {{ max-width: 60%; margin: 0 10px; }}
.msg-meta {{ font-size: 12px; color: #999; margin-bottom: 4px; }}
.msg-meta.right {{ text-align: right; }}
.bubble {{ padding: 10px 14px; border-radius: 8px; font-size: 15px; line-height: 1.6; word-break: break-word; }}
.me-bubble {{ background: #12b7f3; color: white; }}
.other-bubble {{ background: white; color: #333; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }}
.footer {{ text-align: center; color: #999; padding: 30px; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
    <h1>🐧 {html_mod.escape(display_name)}</h1>
    <div class="info">{type_label} · 共 {len(messages)} 条消息</div>
    <div class="toolbar">
        <label>📅 跳转到:</label>
        <select id="dateSelect" onchange="jumpToDate()">
            <option value="">-- 选择日期 --</option>
            {date_options}
        </select>
    </div>
</div>
<div class="chat-container">
    {''.join(parts)}
    <div class="footer">--- 共 {len(messages)} 条消息 ---</div>
</div>
<script>
function jumpToDate() {{
    var sel = document.getElementById('dateSelect');
    var val = sel.value;
    if (!val) return;
    var el = document.getElementById('date-' + val);
    if (el) {{
        el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
}}
</script>
</body>
</html>'''
        
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _export_txt(self, display_name, messages, out_path, chat_type='private'):
        """导出为TXT
        
        Args:
            display_name: 聊天对象名称（私聊=备注名, 群聊=群名）
            messages: 消息列表
            out_path: 输出路径
            chat_type: 'private' 或 'group'
        """
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(f"# QQ聊天记录 - {display_name}\n")
            f.write(f"# 消息数: {len(messages)} | 导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write("=" * 60 + "\n\n")
            
            for msg in messages:
                ts = msg.get('timestamp', 0)
                try:
                    time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else '未知时间'
                except:
                    time_str = '未知时间'
                
                is_me = msg.get('is_me', False)
                if chat_type == 'group':
                    # 群聊：保留各人的sender_name，不替换成群名
                    if is_me:
                        sender_name = '我'
                    else:
                        sender_name = msg.get('sender_name', '') or f'QQ{msg.get("sender_uin", "")}'
                else:
                    # 私聊：对方用备注名（display_name）
                    sender_name = '我' if is_me else display_name
                content = msg.get('text', '')
                # 多元素消息（表情+文本+链接等）用空格连接，避免产生无时间戳的孤立行
                content = content.replace('\n', ' ').strip()
                
                f.write(f"[{time_str}] {sender_name}: {content}\n")
    
    def _export_json(self, display_name, messages, out_path, chat_type='private'):
        """导出为JSON（观己格式）
        
        Args:
            display_name: 聊天对象名称（私聊=备注名, 群聊=群名）
            messages: 消息列表
            out_path: 输出路径
            chat_type: 'private' 或 'group'
        """
        data = {
            "friend_name": display_name,
            "source": "qq",
            "messages": []
        }
        
        for msg in messages:
            ts = msg.get('timestamp', 0)
            try:
                time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else ''
            except:
                time_str = ''
            
            is_me = msg.get('is_me', False)
            content = msg.get('text', '')
            # 多元素消息用空格连接
            content = content.replace('\n', ' ').strip()
            
            msg_chat_type = msg.get('chat_type', 'private')
            # 私聊：qq_number是聊天对象；群聊：qq_number是发送者
            qq_number = msg.get('peer_uin', '') if msg_chat_type == 'private' else msg.get('sender_uin', '')
            
            # 发送者名称：私聊用备注名，群聊保留各人sender_name
            if chat_type == 'group':
                if is_me:
                    sender_name = '我'
                else:
                    sender_name = msg.get('sender_name', '') or f'QQ{msg.get("sender_uin", "")}'
            else:
                sender_name = '我' if is_me else display_name
            
            data["messages"].append({
                "source": "qq",
                "sender": "me" if is_me else "other",
                "sender_name": sender_name,
                "content": content,
                "timestamp": time_str,
                "chat_with": display_name,
                "chat_type": msg_chat_type,
                "qq_number": qq_number,
            })
        
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# ============ GUI ============
class QQExportGUI(QMainWindow):
    _open_preview_signal = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🐧 QQ聊天记录导出工具 v1.0")
        self.setMinimumSize(800, 700)
        self.setStyleSheet(self._get_style())
        
        self.signals = WorkerSignals()
        self.signals.log.connect(self.add_log)
        self.signals.progress.connect(self.update_progress)
        self.signals.step_done.connect(self.on_step_done)
        self.signals.all_done.connect(self.on_all_done)
        self.signals.chat_list.connect(self.on_chat_list)
        
        self._open_preview_signal.connect(self._on_preview_ready)
        
        self.exporter = None
        self.chat_data = []
        self.current_filter = "all"
        self.current_step = 0
        self._db_conn = None
        
        self._init_ui()
        self._check_admin()
        QTimer.singleShot(500, self._detect_wrapper_on_startup)  # 启动时只检测wrapper.node
    
    def _get_style(self):
        return """
        QMainWindow { background: #1a1a2e; }
        QGroupBox { 
            color: #12b7f3; border: 1px solid #2a2a4a; border-radius: 8px; 
            margin-top: 12px; padding-top: 16px; font-weight: bold; font-size: 13px;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; }
        QLabel { color: #c0c0c0; font-size: 12px; }
        QLabel#title { color: #12b7f3; font-size: 22px; font-weight: bold; }
        QLabel#step_label { color: #12b7f3; font-size: 14px; font-weight: bold; }
        QTextEdit#logArea { 
            background: #0a0a1e; color: #c0c0c0; border: 1px solid #2a2a4a; border-radius: 6px;
            font-family: 'Consolas', 'Microsoft YaHei'; font-size: 11px; padding: 6px;
        }
        QPushButton {
            background: #12b7f3; color: white; border: none; border-radius: 6px;
            padding: 10px 20px; font-size: 13px; font-weight: bold;
        }
        QPushButton:hover { background: #0e9fd4; }
        QPushButton:pressed { background: #0a87b5; }
        QPushButton:disabled { background: #2a2a4a; color: #666; }
        QPushButton#danger { background: #e74c3c; }
        QPushButton#danger:hover { background: #c0392b; }
        QPushButton#secondary { background: #2a2a4a; color: #aaa; border: 1px solid #444; border-radius: 4px; padding: 4px 8px; font-size: 11px; }
        QPushButton#secondary:hover { background: #3a3a5a; color: #ddd; }
        QPushButton#secondary:checked { background: #12b7f3; color: white; border: 1px solid #12b7f3; }
        QPushButton#browse { background: #2a2a4a; color: #12b7f3; border: 1px solid #12b7f3; border-radius: 4px; padding: 5px 10px; font-size: 11px; }
        QPushButton#browse:hover { background: #1a3a5a; }
        QProgressBar {
            background: #2a2a4a; border: none; border-radius: 4px; height: 8px;
            text-align: center; color: transparent;
        }
        QProgressBar::chunk { background: #12b7f3; border-radius: 4px; }
        QTableWidget {
            background: #0f0f23; color: #c0c0c0; border: 1px solid #2a2a4a; border-radius: 6px;
            gridline-color: #2a2a4a; font-size: 12px;
        }
        QTableWidget::item { padding: 4px; }
        QTableWidget::item:selected { background: #12b7f3; color: white; }
        QHeaderView::section {
            background: #16213e; color: #12b7f3; border: none; padding: 6px;
            font-weight: bold; font-size: 12px;
        }
        QCheckBox { color: #c0c0c0; font-size: 12px; }
        QCheckBox::indicator { width: 16px; height: 16px; }
        QLineEdit {
            background: #0f0f23; color: #c0c0c0; border: 1px solid #2a2a4a;
            border-radius: 4px; padding: 6px 10px; font-size: 12px;
        }
        QLineEdit:focus { border-color: #12b7f3; }
        QStatusBar { background: #16213e; color: #666; font-size: 11px; }
        QSplitter::handle { background: #2a2a4a; height: 3px; }
        """
    
    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 12, 20, 12)
        layout.setSpacing(8)
        
        # ===== 顶部区域 =====
        # 标题 + 步骤
        title_layout = QHBoxLayout()
        title = QLabel("🐧 QQ聊天记录导出工具")
        title.setObjectName("title")
        title_layout.addWidget(title)
        title_layout.addStretch()
        self.step_label = QLabel("准备就绪 — 点击「扫描聊天」开始")
        self.step_label.setObjectName("step_label")
        title_layout.addWidget(self.step_label)
        layout.addLayout(title_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # ===== 配置区 =====
        config_group = QGroupBox("📂 路径配置")
        config_layout = QVBoxLayout(config_group)
        config_layout.setSpacing(6)
        
        # 第一行：QQ号 + 自动检测按钮
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("我的QQ号:"))
        self.input_qq_number = QLineEdit()
        self.input_qq_number.setPlaceholderText("输入你的QQ号，如 1243592024")
        self.input_qq_number.setMinimumWidth(160)
        row1.addWidget(self.input_qq_number)
        btn_auto_detect = QPushButton("🔍 自动检测路径")
        btn_auto_detect.setObjectName("scanBtn")
        btn_auto_detect.setMinimumHeight(28)
        btn_auto_detect.clicked.connect(self._on_auto_detect_clicked)
        row1.addWidget(btn_auto_detect)
        row1.addStretch()
        config_layout.addLayout(row1)
        
        # 第二行：QQ数据目录（自动填充 + 手动浏览）
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("QQ数据目录:"))
        self.input_qq_dir = QLineEdit()
        self.input_qq_dir.setPlaceholderText("输入QQ号后点击「自动检测路径」，或手动浏览")
        self.input_qq_dir.setMinimumWidth(400)
        row2.addWidget(self.input_qq_dir)
        btn_browse_dir = QPushButton("📁 浏览")
        btn_browse_dir.setObjectName("browse")
        btn_browse_dir.clicked.connect(self._browse_qq_dir)
        row2.addWidget(btn_browse_dir)
        config_layout.addLayout(row2)
        
        # 第三行：wrapper.node（自动填充 + 手动浏览）
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("wrapper.node:"))
        self.input_wrapper = QLineEdit()
        self.input_wrapper.setPlaceholderText("自动检测（如 D:\\QQNT\\versions\\...\\wrapper.node）")
        self.input_wrapper.setMinimumWidth(400)
        row3.addWidget(self.input_wrapper)
        btn_browse_wrapper = QPushButton("📁 浏览")
        btn_browse_wrapper.setObjectName("browse")
        btn_browse_wrapper.clicked.connect(self._browse_wrapper)
        row3.addWidget(btn_browse_wrapper)
        config_layout.addLayout(row3)
        
        layout.addWidget(config_group)
        
        # ===== 操作区 =====
        action_layout = QHBoxLayout()
        
        self.btn_scan = QPushButton("🔍 一键扫描聊天")
        self.btn_scan.setMinimumHeight(40)
        self.btn_scan.clicked.connect(self.on_scan_chat)
        
        self.btn_export = QPushButton("📤 导出选中的聊天")
        self.btn_export.setMinimumHeight(40)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.on_export)
        
        self.btn_open = QPushButton("📂 打开输出目录")
        self.btn_open.setObjectName("secondary")
        self.btn_open.clicked.connect(self.open_output_dir)
        
        action_layout.addWidget(self.btn_scan, 2)
        action_layout.addWidget(self.btn_export, 2)
        action_layout.addWidget(self.btn_open, 1)
        layout.addLayout(action_layout)
        
        # ===== 选项行 =====
        opt_layout = QHBoxLayout()
        self.cb_html = QCheckBox("HTML格式")
        self.cb_html.setChecked(True)
        self.cb_txt = QCheckBox("TXT格式")
        self.cb_txt.setChecked(False)
        self.cb_json = QCheckBox("JSON格式")
        self.cb_json.setChecked(False)
        
        opt_layout.addWidget(self.cb_html)
        opt_layout.addWidget(self.cb_txt)
        opt_layout.addWidget(self.cb_json)
        opt_layout.addSpacing(20)
        
        # 筛选按钮
        opt_layout.addWidget(QLabel("筛选:"))
        self.btn_filter_all = QPushButton("全部")
        self.btn_filter_all.setObjectName("secondary")
        self.btn_filter_all.setMinimumWidth(55)
        self.btn_filter_all.setCheckable(True)
        self.btn_filter_all.setChecked(True)
        self.btn_filter_all.clicked.connect(lambda: self.filter_chats("all"))
        
        self.btn_filter_private = QPushButton("👤 私聊")
        self.btn_filter_private.setObjectName("secondary")
        self.btn_filter_private.setMinimumWidth(70)
        self.btn_filter_private.setCheckable(True)
        self.btn_filter_private.clicked.connect(lambda: self.filter_chats("private"))
        
        self.btn_filter_group = QPushButton("👥 群聊")
        self.btn_filter_group.setObjectName("secondary")
        self.btn_filter_group.setMinimumWidth(70)
        self.btn_filter_group.setCheckable(True)
        self.btn_filter_group.clicked.connect(lambda: self.filter_chats("group"))
        
        opt_layout.addWidget(self.btn_filter_all)
        opt_layout.addWidget(self.btn_filter_private)
        opt_layout.addWidget(self.btn_filter_group)
        opt_layout.addStretch()
        layout.addLayout(opt_layout)
        
        # ===== 中间分割区域（聊天列表 + 日志）=====
        splitter = QSplitter(Qt.Vertical)
        
        # -- 聊天列表 --
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(4)
        
        # 聊天列表顶栏
        top_bar = QHBoxLayout()
        self.chat_stats_label = QLabel("")
        self.chat_stats_label.setStyleSheet("color: #888; font-size: 11px; padding: 2px 6px;")
        top_bar.addWidget(self.chat_stats_label)
        top_bar.addStretch()
        
        search_label = QLabel("🔍")
        search_label.setStyleSheet("color: #12b7f3; font-size: 14px;")
        top_bar.addWidget(search_label)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索QQ号/昵称...")
        self.search_input.setMaximumWidth(200)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: #0f0f23; color: #c0c0c0; border: 1px solid #2a2a4a;
                border-radius: 4px; padding: 4px 8px; font-size: 11px;
            }
            QLineEdit:focus { border-color: #12b7f3; }
        """)
        self.search_input.textChanged.connect(self.on_search_chat)
        top_bar.addWidget(self.search_input)
        chat_layout.addLayout(top_bar)
        
        # 聊天表格
        self.chat_table = QTableWidget()
        self.chat_table.setColumnCount(5)
        self.chat_table.setHorizontalHeaderLabels(["✓", "类型", "QQ号/群号", "昵称", "消息数"])
        self.chat_table.verticalHeader().setVisible(False)
        self._header_check = QCheckBox(self.chat_table.horizontalHeader())
        self._header_check.setChecked(True)
        self._header_check.stateChanged.connect(self._on_header_check_changed)
        self.chat_table.setHorizontalHeaderItem(0, QTableWidgetItem(""))
        self.chat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.chat_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.chat_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.chat_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.chat_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self.chat_table.setColumnWidth(0, 36)
        self.chat_table.setColumnWidth(1, 50)
        self.chat_table.setColumnWidth(4, 70)
        self.chat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.chat_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.chat_table.setMouseTracking(True)
        self.chat_table.cellClicked.connect(self.on_chat_clicked)
        self.chat_table.itemChanged.connect(self._on_table_item_changed)
        self.chat_table.cellEntered.connect(self._on_cell_entered)
        self._hover_row = -1
        chat_layout.addWidget(self.chat_table)
        
        # -- 日志区 --
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(2)
        
        log_title = QLabel("📋 运行日志")
        log_title.setStyleSheet("color: #12b7f3; font-size: 12px; font-weight: bold; padding: 2px 4px;")
        log_layout.addWidget(log_title)
        
        self.log_area = QTextEdit()
        self.log_area.setObjectName("logArea")
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(180)
        log_layout.addWidget(self.log_area)
        
        splitter.addWidget(chat_widget)
        splitter.addWidget(log_widget)
        splitter.setSizes([400, 180])
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter, 1)
        
        self.chat_table.horizontalHeader().geometriesChanged.connect(self._position_header_check)
        self.chat_table.horizontalHeader().sectionResized.connect(self._position_header_check)
        
        # 状态栏
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("🐧 QQ聊天记录导出工具 v1.0 — 就绪")
    
    def _browse_qq_dir(self):
        """浏览选择QQ数据目录"""
        current = self.input_qq_dir.text().strip()
        start_dir = current if current and os.path.exists(current) else ""
        dir_path = QFileDialog.getExistingDirectory(self, "选择QQ数据目录", start_dir)
        if dir_path:
            self.input_qq_dir.setText(dir_path)
            # 尝试从目录名提取QQ号
            dirname = os.path.basename(dir_path)
            if dirname.isdigit():
                self.input_qq_number.setText(dirname)
    
    def _browse_wrapper(self):
        """浏览选择wrapper.node"""
        # 用当前已填写的路径作为起始目录，否则用默认位置
        current = self.input_wrapper.text().strip()
        start_dir = os.path.dirname(current) if current and os.path.exists(os.path.dirname(current)) else ""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择wrapper.node", start_dir,
            "Node文件 (wrapper.node);;所有文件 (*.*)"
        )
        if file_path:
            self.input_wrapper.setText(file_path)
    
    def _check_admin(self):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                self.add_log("⚠️ 当前非管理员权限，密钥提取可能失败！", "warn")
                self.add_log("请右键 → 以管理员身份运行本工具", "warn")
            else:
                self.add_log("✅ 管理员权限检测通过", "success")
        except:
            pass
    
    def _detect_wrapper_on_startup(self):
        """启动时自动检测QQ安装目录和wrapper.node（不需要QQ号）"""
        self.add_log("🔍 正在检测QQ安装环境...")
        
        silent_signals = WorkerSignals()
        exporter = QQExporter(silent_signals, "")
        
        # 检测QQ安装目录和wrapper.node
        qq_install_dir = exporter.find_qq_install_dir()
        if qq_install_dir:
            self.add_log(f"✅ 找到QQ安装目录: {qq_install_dir}", "success")
            exporter.qq_install_dir = qq_install_dir
            wrapper_path = exporter.find_wrapper_node()
            if wrapper_path:
                self.input_wrapper.setText(wrapper_path)
                version = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(wrapper_path))))
                self.add_log(f"✅ 找到wrapper.node: {version}", "success")
            else:
                self.add_log("⚠️ 找到QQ安装目录但未找到wrapper.node", "warn")
        else:
            self.add_log("⚠️ 未找到QQ安装目录，请手动设置wrapper.node路径", "warn")
        
        # 检查sqlcipher3是否已安装
        try:
            from sqlcipher3 import dbapi2
            self.add_log("✅ sqlcipher3 已安装", "success")
        except ImportError:
            self.add_log("⚠️ sqlcipher3 未安装，扫描时将自动尝试安装", "warn")
        
        self.add_log("💡 请输入QQ号后点击「自动检测路径」来定位数据目录", "info")
    
    def _on_auto_detect_clicked(self):
        """用户点击「自动检测路径」按钮"""
        qq_number = self.input_qq_number.text().strip()
        if not qq_number:
            QMessageBox.information(self, "提示", "请先输入你的QQ号！\n\n输入QQ号后，工具会自动搜索对应的QQ数据目录和wrapper.node。")
            self.input_qq_number.setFocus()
            return
        self._auto_detect(qq_number)
    
    def _auto_detect(self, qq_number=""):
        """自动检测QQ安装路径和数据目录
        
        Args:
            qq_number: 用户QQ号，传入时精准匹配该QQ号的数据目录
        """
        if qq_number:
            self.add_log(f"🔍 正在根据QQ号 {qq_number} 自动检测路径...")
        else:
            self.add_log("🔍 正在自动检测QQ环境...")
        
        # 创建临时exporter来复用检测逻辑（静默模式，不输出重复日志）
        silent_signals = WorkerSignals()
        exporter = QQExporter(silent_signals, "")
        
        # === 检测QQ安装目录和wrapper.node ===
        qq_install_dir = exporter.find_qq_install_dir()
        
        if qq_install_dir:
            self.add_log(f"✅ 找到QQ安装目录: {qq_install_dir}", "success")
            # 查找wrapper.node
            exporter.qq_install_dir = qq_install_dir
            wrapper_path = exporter.find_wrapper_node()
            if wrapper_path:
                self.input_wrapper.setText(wrapper_path)
                version = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(wrapper_path))))
                self.add_log(f"✅ 找到wrapper.node: {version}", "success")
            else:
                self.add_log("⚠️ 找到QQ安装目录但未找到wrapper.node", "warn")
        else:
            self.add_log("⚠️ 未找到QQ安装目录，请手动设置wrapper.node路径", "warn")
        
        # === 检测QQ数据目录（根据QQ号精准匹配） ===
        qq_data_dir = exporter.find_qq_data_dir(qq_number=qq_number)
        
        if qq_data_dir:
            self.input_qq_dir.setText(qq_data_dir)
            self.add_log(f"✅ 找到QQ数据目录: {qq_data_dir}", "success")
        else:
            if qq_number:
                self.add_log(f"⚠️ 未找到QQ号 {qq_number} 对应的数据目录", "warn")
                self.add_log("请确认QQ号是否正确，或手动浏览选择数据目录", "warn")
            else:
                self.add_log("⚠️ 未自动检测到QQ数据目录，请手动输入", "warn")
        
        # === 检查sqlcipher3是否已安装 ===
        try:
            from sqlcipher3 import dbapi2
            self.add_log("✅ sqlcipher3 已安装", "success")
        except ImportError:
            self.add_log("⚠️ sqlcipher3 未安装，扫描时将自动尝试安装", "warn")
            self.add_log("如果自动安装失败，请手动执行: pip install sqlcipher3", "warn")
    
    def add_log(self, msg, level="info"):
        """添加日志到日志区"""
        color_map = {
            "info": "#b0b0b0", 
            "success": "#12b7f3", 
            "warn": "#f39c12", 
            "error": "#e74c3c"
        }
        color = color_map.get(level, "#b0b0b0")
        ts = datetime.now().strftime("%H:%M:%S")
        
        # 添加到日志区
        self.log_area.append(f'<span style="color:#666">[{ts}]</span> <span style="color:{color}">{msg}</span>')
        self.log_area.moveCursor(QTextCursor.End)
        
        # 更新状态栏
        self.status.showMessage(f"[{ts}] {msg}", 5000)
        if level == "error":
            self.step_label.setText(f"❌ {msg[:50]}")
        elif level == "success":
            self.step_label.setText(f"✅ {msg[:50]}")
    
    def update_progress(self, current, total):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status.showMessage(f"进度: {current}/{total} ({pct}%)")
    
    def set_busy(self, busy=True):
        self.btn_scan.setEnabled(not busy)
        self.btn_export.setEnabled(not busy and bool(self.chat_data))
        if busy:
            self.btn_scan.setText("⏳ 扫描中...")
        else:
            self.btn_scan.setText("🔍 一键扫描聊天")
    
    # ===== 扫描聊天 =====
    def on_scan_chat(self):
        qq_data_dir = self.input_qq_dir.text().strip()
        qq_number = self.input_qq_number.text().strip()
        wrapper_path = self.input_wrapper.text().strip()
        
        if not qq_data_dir or not os.path.exists(qq_data_dir):
            QMessageBox.warning(self, "提示", "请设置QQ数据目录！\n\n输入QQ号后点击「自动检测路径」即可自动搜索，\n或点击「浏览」手动选择数据目录。")
            return
        
        if not qq_number:
            QMessageBox.warning(self, "提示", "请输入你的QQ号！\n\nQQ号用于定位数据目录和区分「我」与「对方」的消息。\n输入QQ号后点击「自动检测路径」即可自动搜索。")
            return
        
        # 检查nt_qq目录是否存在
        nt_qq_path = os.path.join(qq_data_dir, "nt_qq")
        if not os.path.exists(nt_qq_path):
            reply = QMessageBox.question(
                self, "提示",
                f"未在 {qq_data_dir} 下找到 nt_qq 目录。\n\n"
                f"请确认这是正确的QQ数据目录（通常在 QQ号 文件夹下有 nt_qq 子目录）。\n\n是否继续？",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        self.set_busy(True)
        self.progress_bar.setValue(0)
        self.current_step = 0
        self.log_area.clear()
        self.add_log(f"🚀 开始扫描 — QQ号: {qq_number}, 数据目录: {qq_data_dir}")
        
        def run():
            nonlocal wrapper_path
            try:
                output_dir = self._get_output_dir()
                self.exporter = QQExporter(self.signals, output_dir)
                self.exporter.qq_data_dir = qq_data_dir
                self.exporter.my_qq = qq_number
                
                # Step 1: 查找数据库
                self.signals.step_done.emit("find_db")
                db_files = self.exporter.find_databases(qq_data_dir)
                
                if not db_files:
                    self.signals.all_done.emit(False, "未找到任何数据库文件！\n请确认QQ数据目录路径正确。")
                    return
                
                # 优先使用nt_msg.db
                main_db = None
                for db in db_files:
                    if 'nt_msg.db' in os.path.basename(db):
                        main_db = db
                        break
                if not main_db:
                    main_db = db_files[0]
                
                self.signals.log.emit(f"使用主数据库: {os.path.basename(main_db)}", "info")
                
                # Step 2: 提取密钥
                self.signals.step_done.emit("extract_key")
                
                # 先尝试自动查找wrapper.node
                if not wrapper_path:
                    qq_install_dir = self.exporter.find_qq_install_dir()
                    if qq_install_dir:
                        self.exporter.qq_install_dir = qq_install_dir
                        wrapper_path = self.exporter.find_wrapper_node() or ""
                
                if not wrapper_path:
                    self.signals.all_done.emit(False, 
                        "未找到wrapper.node！\n\n"
                        "请手动设置wrapper.node路径（在QQ安装目录的 versions\\版本号\\resources\\app\\ 下）。\n\n"
                        "提示：密钥提取会自动以调试模式启动QQ，你只需要登录即可。")
                    return
                
                key = self.exporter.extract_key(wrapper_path)
                if not key:
                    self.signals.all_done.emit(False, 
                        "密钥提取失败！\n\n"
                        "请确保：\n"
                        "1. 以管理员权限运行本工具\n"
                        "2. wrapper.node路径正确\n"
                        "3. 调试器法会在启动QQ后等你登录，登录成功后自动截获密钥\n"
                        "4. 如果QQ已运行，工具会自动关闭再重新启动")
                    return
                self.exporter.key = key
                
                # Step 3: 解密数据库
                self.signals.step_done.emit("decrypt")
                conn = self.exporter.decrypt_database(main_db, key)
                if not conn:
                    self.signals.all_done.emit(False, "数据库解密失败！请检查密钥是否正确。")
                    return
                self._db_conn = conn
                
                # Step 4: 扫描聊天
                self.signals.step_done.emit("scan_chats")
                chat_list = self.exporter.scan_chats(conn, qq_number)
                
                if not chat_list:
                    self.signals.all_done.emit(False, "扫描完成但未找到有效的聊天记录。")
                    return
                
                self.signals.chat_list.emit(chat_list)
                self.signals.all_done.emit(True, f"扫描完成！共 {len(chat_list)} 个聊天")
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.signals.all_done.emit(False, f"错误: {e}")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ===== 导出 =====
    def on_export(self):
        if not self.chat_data:
            QMessageBox.warning(self, "提示", "请先扫描聊天！")
            return
        
        selected = []
        for i in range(self.chat_table.rowCount()):
            item = self.chat_table.item(i, 0)
            if item and item.checkState() == Qt.Checked:
                idx = item.data(Qt.UserRole)
                if idx is not None and 0 <= idx < len(self.chat_data):
                    selected.append(self.chat_data[idx])
        
        if not selected:
            QMessageBox.warning(self, "提示", "请至少勾选一个聊天！")
            return
        
        self.set_busy(True)
        self.add_log(f"📤 开始导出 {len(selected)} 个聊天...")
        
        def run():
            try:
                export_html = self.cb_html.isChecked()
                export_txt = self.cb_txt.isChecked()
                export_json = self.cb_json.isChecked()
                if not export_html and not export_txt and not export_json:
                    export_html = True
                
                fmt = ""
                if export_html: fmt += "html"
                if export_txt: fmt += "txt"
                if export_json: fmt += "json"
                
                self.exporter.export_chats(selected, fmt)
                self.signals.all_done.emit(True, f"导出完成！共 {len(selected)} 个聊天")
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.signals.all_done.emit(False, f"导出失败: {e}")
        
        threading.Thread(target=run, daemon=True).start()
    
    def on_step_done(self, step):
        step_names = {
            "find_db": "🔍 查找数据库", 
            "extract_key": "🔑 提取密钥", 
            "decrypt": "🔓 解密数据库", 
            "scan_chats": "📋 扫描聊天记录", 
            "export": "📤 导出聊天记录"
        }
        name = step_names.get(step, step)
        self.step_label.setText(f"⏳ {name}...")
        self.add_log(f"--- {name} ---")
    
    def on_all_done(self, success, msg):
        self.set_busy(False)
        self.progress_bar.setValue(100 if success else 0)
        if success:
            self.step_label.setText(f"✅ {msg}")
            self.add_log(f"✅ {msg}", "success")
        else:
            self.step_label.setText(f"❌ {msg[:60]}")
            self.add_log(f"❌ {msg}", "error")
            QMessageBox.critical(self, "操作失败", msg)
    
    def on_chat_list(self, chat_list):
        self.chat_data = chat_list
        self.chat_index_map = {}
        for i, c in enumerate(chat_list):
            self.chat_index_map[c['peer_uin']] = i
        self.current_filter = "all"
        self._populate_chat_table(chat_list)
        
        group_count = sum(1 for c in chat_list if c['is_group'])
        private_count = len(chat_list) - group_count
        total_msgs = sum(c['msg_count'] for c in chat_list)
        self.chat_stats_label.setText(
            f"共 {len(chat_list)} 个聊天 | 👤 私聊: {private_count} | 👥 群聊: {group_count} | 💬 消息: {total_msgs}"
        )
        
        self.btn_export.setEnabled(True)
        self.add_log(f"📊 聊天列表已加载: {private_count}个私聊, {group_count}个群聊, 共{total_msgs}条消息", "success")
    
    def _populate_chat_table(self, chat_list):
        self.chat_table.blockSignals(True)
        self.chat_table.setRowCount(len(chat_list))
        for i, chat in enumerate(chat_list):
            orig_idx = self.chat_index_map.get(chat['peer_uin'], i)
            
            # 勾选框
            check_item = QTableWidgetItem()
            check_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            check_item.setCheckState(Qt.Checked)
            check_item.setData(Qt.UserRole, orig_idx)
            self.chat_table.setItem(i, 0, check_item)
            
            # 类型
            type_text = "👥" if chat['is_group'] else "👤"
            type_item = QTableWidgetItem(type_text)
            type_item.setTextAlignment(Qt.AlignCenter)
            type_item.setForeground(QColor("#12b7f3"))
            self.chat_table.setItem(i, 1, type_item)
            
            # QQ号/群号
            uin_item = QTableWidgetItem(chat['peer_uin'])
            uin_item.setForeground(QColor("#12b7f3"))
            self.chat_table.setItem(i, 2, uin_item)
            
            # 昵称
            nick_item = QTableWidgetItem(chat.get('display_name', chat['peer_uin']))
            nick_item.setForeground(QColor("#bbb"))
            self.chat_table.setItem(i, 3, nick_item)
            
            # 消息数
            count_item = QTableWidgetItem(str(chat['msg_count']))
            count_item.setTextAlignment(Qt.AlignCenter)
            self.chat_table.setItem(i, 4, count_item)
        
        self.chat_table.blockSignals(False)
        self._sync_header_check_state()
        QTimer.singleShot(0, self._position_header_check)
    
    def filter_chats(self, filter_type):
        self.current_filter = filter_type
        self.btn_filter_all.setChecked(filter_type == "all")
        self.btn_filter_private.setChecked(filter_type == "private")
        self.btn_filter_group.setChecked(filter_type == "group")
        
        if filter_type == "all":
            filtered = self.chat_data
        elif filter_type == "private":
            filtered = [c for c in self.chat_data if not c['is_group']]
        elif filter_type == "group":
            filtered = [c for c in self.chat_data if c['is_group']]
        else:
            filtered = self.chat_data
        self._populate_chat_table(filtered)
    
    def on_search_chat(self, text):
        text = text.strip().lower()
        if not text:
            self.filter_chats(self.current_filter)
            return
        
        if self.current_filter == "private":
            base = [c for c in self.chat_data if not c['is_group']]
        elif self.current_filter == "group":
            base = [c for c in self.chat_data if c['is_group']]
        else:
            base = self.chat_data
        
        filtered = [c for c in base if
            text in c.get('display_name', '').lower() or
            text in c.get('peer_uin', '').lower()
        ]
        self._populate_chat_table(filtered)
    
    def on_chat_clicked(self, row, col):
        """单击聊天行打开HTML预览"""
        if col == 0:
            return
        item = self.chat_table.item(row, 0)
        if not item:
            return
        idx = item.data(Qt.UserRole)
        if idx is None or idx < 0 or idx >= len(self.chat_data):
            return
        
        chat = self.chat_data[idx]
        self.set_busy(True)
        self.step_label.setText("⏳ 正在生成预览...")
        self.add_log(f"正在加载 {chat['display_name']} 的聊天预览...")
        
        def load_and_show():
            try:
                html_path = self._generate_chat_preview(chat)
                self._open_preview_signal.emit(html_path)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.signals.all_done.emit(False, f"加载聊天失败: {e}")
        
        threading.Thread(target=load_and_show, daemon=True).start()
    
    def _generate_chat_preview(self, chat):
        """生成聊天预览HTML"""
        display_name = chat['display_name']
        messages = chat['messages']
        is_group = chat.get('is_group', False)
        
        import html as html_mod
        
        parts = []
        last_date = ''
        
        for msg in messages:
            ts = msg.get('timestamp', 0)
            if not ts:
                continue
            try:
                dt = datetime.fromtimestamp(ts)
            except:
                continue
            
            date_str = dt.strftime('%Y年%m月%d日')
            date_id = dt.strftime('%Y-%m-%d')
            time_str = dt.strftime('%H:%M')
            
            if date_str != last_date:
                parts.append(f'<div class="date-sep" id="date-{date_id}"><span>{date_str}</span></div>')
                last_date = date_str
            
            is_me = msg.get('is_me', False)
            # 群聊预览：保留各人sender_name；私聊：用备注名
            if is_group:
                if is_me:
                    sender_name = '我'
                else:
                    sender_name = msg.get('sender_name', '') or f'QQ{msg.get("sender_uin", "")}'
                sender_name = html_mod.escape(sender_name)
            else:
                sender_name = '我' if is_me else html_mod.escape(display_name)
            content = html_mod.escape(msg.get('text', '')).replace('\n', '<br>')
            
            if is_me:
                parts.append(f'''
                <div class="msg-row me">
                    <div class="avatar avatar-me">我</div>
                    <div class="msg-body">
                        <div class="msg-meta right">我 {time_str}</div>
                        <div class="bubble me-bubble">{content}</div>
                    </div>
                </div>''')
            else:
                parts.append(f'''
                <div class="msg-row other">
                    <div class="avatar avatar-other">{html_mod.escape(sender_name[0] if sender_name else "?")}</div>
                    <div class="msg-body">
                        <div class="msg-meta">{sender_name} {time_str}</div>
                        <div class="bubble other-bubble">{content}</div>
                    </div>
                </div>''')
        
        # 日期选项
        date_set = []
        seen_dates = set()
        for msg in messages:
            ts = msg.get('timestamp', 0)
            if ts:
                try:
                    ds = datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
                    if ds not in seen_dates:
                        seen_dates.add(ds)
                        date_set.append(ds)
                except:
                    pass
        date_options = ''.join(f'<option value="{d}">{d}</option>' for d in date_set)
        
        type_label = "群聊" if is_group else "私聊"
        
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QQ聊天记录 - {html_mod.escape(display_name)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; background: #f5f5f5; color: #333; }}
.header {{ background: #12b7f3; color: white; padding: 16px 20px; position: sticky; top: 0; z-index: 10; }}
.header h1 {{ font-size: 17px; font-weight: 500; }}
.header .info {{ font-size: 12px; color: rgba(255,255,255,0.85); margin-top: 4px; }}
.toolbar {{ display: flex; align-items: center; gap: 10px; margin-top: 8px; }}
.toolbar label {{ font-size: 12px; color: rgba(255,255,255,0.8); }}
.toolbar select {{ border: 1px solid rgba(255,255,255,0.3); border-radius: 4px; padding: 4px 8px; font-size: 12px; background: rgba(255,255,255,0.2); color: white; cursor: pointer; }}
.toolbar select option {{ background: #333; color: white; }}
.chat-container {{ max-width: 800px; margin: 0 auto; padding: 16px 20px; }}
.date-sep {{ text-align: center; margin: 20px 0 12px; }}
.date-sep span {{ background: #dadada; color: #666; padding: 4px 12px; border-radius: 4px; font-size: 12px; }}
.msg-row {{ display: flex; margin-bottom: 16px; align-items: flex-start; }}
.msg-row.me {{ flex-direction: row-reverse; }}
.avatar {{ flex-shrink: 0; width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; color: white; margin-top: 18px; }}
.avatar-me {{ background: #12b7f3; }}
.avatar-other {{ background: #ff9800; }}
.msg-body {{ max-width: 60%; margin: 0 10px; }}
.msg-meta {{ font-size: 12px; color: #999; margin-bottom: 4px; }}
.msg-meta.right {{ text-align: right; }}
.bubble {{ padding: 10px 14px; border-radius: 8px; font-size: 15px; line-height: 1.6; word-break: break-word; }}
.me-bubble {{ background: #12b7f3; color: white; }}
.other-bubble {{ background: white; color: #333; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }}
.footer {{ text-align: center; color: #999; padding: 30px; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
    <h1>🐧 {html_mod.escape(display_name)}</h1>
    <div class="info">{type_label} · 共 {len(messages)} 条消息</div>
    <div class="toolbar">
        <label>📅 跳转到:</label>
        <select id="dateSelect" onchange="jumpToDate()">
            <option value="">-- 选择日期 --</option>
            {date_options}
        </select>
    </div>
</div>
<div class="chat-container">
    {''.join(parts)}
    <div class="footer">--- 共 {len(messages)} 条消息 ---</div>
</div>
<script>
function jumpToDate() {{
    var sel = document.getElementById('dateSelect');
    var val = sel.value;
    if (!val) return;
    var el = document.getElementById('date-' + val);
    if (el) {{
        el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
}}
</script>
</body>
</html>'''
        
        out_dir = os.path.join(self._get_output_dir(), "chat_preview")
        os.makedirs(out_dir, exist_ok=True)
        safe_name = "".join(c if c.isalnum() or c in '_-' else '_' for c in display_name)
        out_path = os.path.join(out_dir, f"{safe_name}_preview.html")
        
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return out_path
    
    def _on_preview_ready(self, html_path):
        self.set_busy(False)
        self.step_label.setText("✅ 聊天预览已生成")
        self.add_log("✅ 聊天预览已生成", "success")
        if html_path and os.path.exists(html_path):
            os.startfile(html_path)
    
    def _get_output_dir(self):
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, "qq_export")
    
    def open_output_dir(self):
        chat_export_dir = os.path.join(self._get_output_dir(), "chat_export")
        if os.path.exists(chat_export_dir):
            os.startfile(chat_export_dir)
        else:
            out_dir = self._get_output_dir()
            if os.path.exists(out_dir):
                os.startfile(out_dir)
            else:
                QMessageBox.information(self, "提示", "输出目录还不存在，请先执行导出")
    
    # ===== 表头复选框相关 =====
    def _position_header_check(self):
        header = self.chat_table.horizontalHeader()
        try:
            x = header.sectionViewportPosition(0)
            w = header.sectionSize(0)
            h = header.height()
            self._header_check.setGeometry(x + (w - 16) // 2, (h - 16) // 2, 16, 16)
            self._header_check.show()
        except:
            pass
    
    def _on_header_check_changed(self, state):
        checked = (state == Qt.Checked)
        self.chat_table.blockSignals(True)
        for i in range(self.chat_table.rowCount()):
            item = self.chat_table.item(i, 0)
            if item:
                item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        self.chat_table.blockSignals(False)
    
    def _sync_header_check_state(self):
        total = self.chat_table.rowCount()
        if total == 0:
            return
        checked_count = 0
        for i in range(total):
            item = self.chat_table.item(i, 0)
            if item and item.checkState() == Qt.Checked:
                checked_count += 1
        self._header_check.blockSignals(True)
        if checked_count == 0:
            self._header_check.setCheckState(Qt.Unchecked)
        elif checked_count == total:
            self._header_check.setCheckState(Qt.Checked)
        else:
            self._header_check.setCheckState(Qt.PartiallyChecked)
        self._header_check.blockSignals(False)
    
    def _on_table_item_changed(self, item):
        if item.column() == 0:
            self._sync_header_check_state()
    
    def _on_cell_entered(self, row, col):
        self.chat_table.viewport().setCursor(Qt.PointingHandCursor)
        if row == self._hover_row:
            return
        if self._hover_row >= 0 and self._hover_row < self.chat_table.rowCount():
            for c in range(self.chat_table.columnCount()):
                item = self.chat_table.item(self._hover_row, c)
                if item:
                    item.setBackground(QColor("#0f0f23") if not item.isSelected() else QColor("#12b7f3"))
        self._hover_row = row
        hover_bg = QColor("#1a3a5a")
        for c in range(self.chat_table.columnCount()):
            item = self.chat_table.item(row, c)
            if item and not item.isSelected():
                item.setBackground(hover_bg)
    
    def closeEvent(self, event):
        """关闭时清理数据库连接"""
        if self._db_conn:
            try:
                self._db_conn.close()
            except:
                pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Microsoft YaHei", 10))
    window = QQExportGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
