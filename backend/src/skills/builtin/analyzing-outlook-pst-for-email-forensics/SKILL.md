---
id: analyzing-outlook-pst-for-email-forensics
name: analyzing-outlook-pst-for-email-forensics
name_zh: 分析·Outlook·PST·邮件·取证
description: 本指南介绍使用 libpff、pst-utils 和电子邮件取证工具分析 Microsoft Outlook PST 和 OST 文件中的邮件内容、头部信息、附件、已删除项目和元数据，适用于法律调查和事件响应。文档包含开源工具和
  Python 脚本的使用方法。
domain: cybersecurity
subdomain: digital-forensics
tags:
- email-forensics
- pst
- ost
- outlook
- mapi
- email-headers
- attachments
- deleted-emails
- libpff
- eml-extraction
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 分析 Outlook PST 文件进行电子邮件取证

## 概述
Microsoft Outlook PST（个人存储表）和 OST（脱机存储表）文件是数字取证调查中的关键证据来源。PST 文件以基于 MAPI（Messaging Application Programming Interface）属性系统的专有二进制格式存储电子邮件、日历事件、联系人、任务和备注。对这些文件的取证分析可实现从“可恢复项目”文件夹中恢复已删除邮件、提取邮件头部追踪路由路径、分析附件中的恶意软件或泄露数据，并重建通信模式。现代 PST 文件使用 Unicode 格式，采用 4KB 分页，最大可扩展至 50GB，而旧版 ANSI 格式限制为 2GB。

## 使用时机
- 当调查需要分析 Outlook PST 文件的电子邮件取证事件时
- 当构建此领域的检测规则或威胁狩猎查询时
- 当 SOC 分析师需要此类分析的结构化流程时
- 当验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- libpff/pffexport（开源 PST 解析器）
- Python 3.8+ 配备 pypff 或 libratom 库
- MailXaminer、Forensic Email Collector 或 SysTools PST Forensics（商业工具）
- Microsoft Outlook（可选，用于原生 PST 访问）
- 足够的磁盘空间存储提取内容

## PST 文件位置

| 来源 | 路径 |
|--------|------|
| Outlook 2016+ 默认 | %USERPROFILE%\Documents\Outlook Files\*.pst |
| Outlook 旧版 | %LOCALAPPDATA%\Microsoft\Outlook\*.pst |
| OST 缓存 | %LOCALAPPDATA%\Microsoft\Outlook\*.ost |
| 归档文件 | %USERPROFILE%\Documents\Outlook Files\archive.pst |

## 使用开源工具分析

### libpff / pffexport

```bash
# 导出 PST 文件中的所有项目
pffexport -m all evidence.pst -t exported_pst

# 仅导出电子邮件消息
pffexport -m items evidence.pst -t exported_emails

# 导出已恢复/已删除项目
pffexport -m recovered evidence.pst -t recovered_items

# 获取 PST 文件信息
pffinfo evidence.pst
```

### Python PST 分析

```python
import pypff
import os
import json
import hashlib
import email
import sys
from datetime import datetime
from collections import defaultdict


class PSTForensicAnalyzer:
    """对 Outlook PST/OST 文件进行取证分析。"""

    def __init__(self, pst_path: str, output_dir: str):
        self.pst_path = pst_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.pst = pypff.file()
        self.pst.open(pst_path)
        self.messages = []
        self.attachments = []
        self.stats = defaultdict(int)

    def process_folder(self, folder, folder_path: str = ""):
        """递归处理 PST 文件夹并提取消息。"""
        folder_name = folder.name or "Root"
        current_path = f"{folder_path}/{folder_name}" if folder_path else folder_name

        for i in range(folder.number_of_sub_messages):
            try:
                message = folder.get_sub_message(i)
                msg_data = self.extract_message(message, current_path)
                if msg_data:
                    self.messages.append(msg_data)
                    self.stats["total_messages"] += 1
            except Exception as e:
                self.stats["parse_errors"] += 1

        for i in range(folder.number_of_sub_folders):
            try:
                subfolder = folder.get_sub_folder(i)
                self.process_folder(subfolder, current_path)
            except Exception:
                continue

    def extract_message(self, message, folder_path: str) -> dict:
        """从单封电子邮件中提取取证元数据。"""
        msg_data = {
            "folder": folder_path,
            "subject": message.subject or "",
            "sender": message.sender_name or "",
            "sender_email": "",
            "creation_time": str(message.creation_time) if message.creation_time else None,
            "delivery_time": str(message.delivery_time) if message.delivery_time else None,
            "modification_time": str(message.modification_time) if message.modification_time else None,
            "has_attachments": message.number_of_attachments > 0,
            "attachment_count": message.number_of_attachments,
            "body_size": len(message.plain_text_body or b""),
            "html_size": len(message.html_body or b""),
        }

        # 提取传输头部用于路由分析
        headers = message.transport_headers
        if headers:
            msg_data["headers_present"] = True
            msg_data["headers_size"] = len(headers)
            # 解析关键头部
            parsed = email.message_from_string(headers)
            msg_data["from_header"] = parsed.get("From", "")
            msg_data["to_header"] = parsed.get("To", "")
            msg_data["date_header"] = parsed.get("Date", "")
            msg_data["message_id"] = parsed.get("Message-ID", "")
            msg_data["x_originating_ip"] = parsed.get("X-Originating-IP", "")
            msg_data["received_headers"] = parsed.get_all("Received", [])

        # 处理附件
        for j in range(message.number_of_attachments):
            try:
                attachment = message.get_attachment(j)
                att_data = {
                    "message_subject": msg_data["subject"],
                    "name": attachment.name or f"attachment_{j}",
                    "size": attachment.size,
                    "content_type": "",
                }
                self.attachments.append(att_data)
                self.stats["total_attachments"] += 1
            except Exception:
                continue

        return msg_data

    def save_attachments(self, max_size_mb: int = 100):
        """将附件保存到磁盘进行分析。"""
        att_dir = os.path.join(self.output_dir, "attachments")
        os.makedirs(att_dir, exist_ok=True)

        root = self.pst.get_root_folder()
        self._save_attachments_recursive(root, att_dir, max_size_mb)

    def _save_attachments_recursive(self, folder, att_dir, max_size_mb):
        for i in range(folder.number_of_sub_messages):
            try:
                message = folder.get_sub_message(i)
                for j in range(message.number_of_attachments):
                    att = message.get_attachment(j)
                    if att.size and att.size < max_size_mb * 1024 * 1024:
                        name = att.name or f"unknown_{i}_{j}"
                        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
                        path = os.path.join(att_dir, safe_name)
                        try:
                            data = att.read_buffer(att.size)
                            with open(path, "wb") as f:
                                f.write(data)
                        except Exception:
                            continue
            except Exception:
                continue

        for i in range(folder.number_of_sub_folders):
            try:
                self._save_attachments_recursive(folder.get_sub_folder(i), att_dir, max_size_mb)
            except Exception:
                continue

    def generate_report(self) -> str:
        """生成 PST 取证分析综合报告。"""
        root = self.pst.get_root_folder()
        self.process_folder(root)

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "pst_file": self.pst_path,
            "pst_size_bytes": os.path.getsize(self.pst_path),
            "statistics": dict(self.stats),
            "messages": self.messages[:500],
            "attachments": self.attachments[:200],
        }

        report_path = os.path.join(self.output_dir, "pst_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[*] 总邮件数: {self.stats['total_messages']}")
        print(f"[*] 总附件数: {self.stats['total_attachments']}")
        print(f"[*] 解析错误: {self.stats['parse_errors']}")
        return report_path

    def close(self):
        self.pst.close()


def main():
    if len(sys.argv) < 3:
        print("用法: python process.py <pst_file> <output_dir>")
        sys.exit(1)
    analyzer = PSTForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()
    analyzer.close()


if __name__ == "__main__":
    main()
```

## 电子邮件头部分析

关键取证分析头部：

| 头部 | 取证价值 |
|--------|---------------|
| Received | 消息路由链（从下至上阅读） |
| X-Originating-IP | 发件人实际 IP 地址 |
| Message-ID | 用于关联的唯一标识符 |
| Date | 发送时间戳 |
| Return-Path | 反弹地址（可能与 From 不同） |
| DKIM-Signature | 域认证签名 |
| Authentication-Results | SPF、DKIM、DMARC 验证结果 |
| X-Mailer | 使用的电子邮件客户端 |

## 参考资料
- MailXaminer PST 取证: https://www.mailxaminer.com/blog/outlook-pst-file-forensics/
- libpff 文档: https://github.com/libyal/libpff
- PST 文件格式规范: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/
- SANS 电子邮件取证: https://www.sans.org/blog/email-forensics/

## 示例输出

```text
$ pffexport /evidence/jsmith_archive.pst -t /analysis/pst_output

pffexport 20231205 - libpff PST/OST 导出工具
=================================================
输入: /evidence/jsmith_archive.pst (2.3 GB)

正在导出 PST 内容...
  文件夹:       45
  邮件:        12,456
  附件:        3,234
  联系人:      567
  日历:        234
  任务:        89

导出完成耗时 3 分 42 秒。

$ python3 pst_analyzer.py /analysis/pst_output /analysis/email_report

PST 取证分析报告
==============================
来源: jsmith_archive.pst (john.smith@corporate.com)
日期范围: 2023-06-01 到 2024-01-18

--- 邮箱统计信息 ---
  总邮件数:       12,456
  已发送:         4,567
  已接收:         7,889
  含附件:         3,234
  已删除（已恢复）: 234

--- 钓鱼/可疑邮件 ---
邮件 #8923
  日期:        2024-01-15 14:30:22 UTC
  来自:        "IT 支持" <it-support@c0rporate-help.com>
  收件人:      john.smith@corporate.com
  主题:        紧急：需要重置密码
  头部:
    Return-Path:    bounce@mail-relay.c0rporate-help.com
    X-Originating-IP: 203.0.113.55
    Received:       from mail-relay.c0rporate-help.com (203.0.113.55)
    SPF:            FAIL (domain c0rporate-help.com)
    DKIM:           NONE
    DMARC:          FAIL
  附件:
    - Password_Reset_Form.xlsm (245 KB) SHA-256: 7a3b8c9d...e1f2a3b4
  正文预览:  "亲爱的员工，您的密码将在 24 小时后过期。
              请打开附件表单以重置凭据..."

--- 数据泄露指标 ---
邮件 #9102
  日期:        2024-01-16 03:15:45 UTC
  来自:        john.smith@corporate.com
  收件人:      j.smith.personal8842@protonmail.com
  主题:        (无主题)
  附件:
    - archive_part1.7z (24.5 MB) - 加密
    - archive_part2.7z (24.5 MB) - 加密

邮件 #9103
  日期:        2024-01-16 03:18:22 UTC
  来自:        john.smith@corporate.com
  收件人:      j.smith.personal8842@protonmail.com
  主题:        回复：
  附件:
    - archive_part3.7z (18.2 MB) - 加密

--- 关键词匹配 ---
  "confidential":     45 封邮件
  "password":         23 封邮件
  "transfer":         12 封邮件
  "resign":           3 封邮件
  "delete evidence":  1 封邮件 (邮件 #9200, 2024-01-17 22:30:00 UTC)

摘要:
  检测到钓鱼邮件:    1 封（初始入侵向量）
  可疑发送邮件:      5 封（含附件发送至个人账户）
  加密附件:          3 个（总计 67.2 MB - 可能的数据泄露）
  报告: /analysis/email_report/pst_forensic_report.json
```