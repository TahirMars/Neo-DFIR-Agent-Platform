"""
证据结构化解析：CSV、JSON、JSONL、TXT、日志等（`evidence_analysis` 子模块）。
"""
import csv
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

# 最大限制
MAX_ROWS = 100000
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


def detect_format(filename: str, content_sample: bytes) -> str:
    """
    自动检测文件格式。
    
    参数：
        filename: 文件名
        content_sample: 文件内容样本（前1024字节）
    
    返回：
        格式名称：csv | json | jsonl | txt
    """
    ext = Path(filename).suffix.lower()
    
    # 基于扩展名
    if ext in ('.csv', '.tsv'):
        return 'csv'
    if ext == '.json':
        return 'json'
    if ext in ('.jsonl', '.ndjson'):
        return 'jsonl'
    if ext in ('.txt', '.log'):
        return 'txt'
    
    # 基于内容
    try:
        text = content_sample.decode('utf-8', errors='ignore')
        
        # 尝试解析为JSON
        if text.strip().startswith('{') or text.strip().startswith('['):
            try:
                json.loads(text)
                return 'json'
            except json.JSONDecodeError:
                pass
        
        # 检查是否为JSONL（每行一个JSON）
        lines = text.split('\n')[:5]
        if all(line.strip().startswith('{') for line in lines if line.strip()):
            return 'jsonl'
        
        # 检查是否为CSV（包含逗号或制表符）
        if ',' in text or '\t' in text:
            return 'csv'
        
        # 默认为文本
        return 'txt'
    except Exception:
        return 'txt'


def detect_csv_delimiter(sample: str) -> str:
    """
    检测 CSV 分隔符。
    
    常见分隔符：, | ; | \t
    """
    delimiters = [',', '\t', ';', '|']
    max_count = 0
    detected = ','
    
    for delimiter in delimiters:
        count = sample.count(delimiter)
        if count > max_count:
            max_count = count
            detected = delimiter
    
    return detected


def parse_csv(
    content: bytes,
    encoding: str = 'utf-8',
    delimiter: str | None = None,
    max_rows: int = MAX_ROWS
) -> dict[str, Any]:
    """
    解析 CSV 文件。
    
    返回：
        {
            "columns": ["col1", "col2", ...],
            "rows": [{"col1": "val1", ...}, ...],
            "total_rows": int,
            "truncated": bool
        }
    """
    try:
        text = content.decode(encoding, errors='replace')
    except Exception:
        text = content.decode('utf-8', errors='replace')
    
    # 自动检测分隔符
    if delimiter is None:
        sample = text[:1024]
        delimiter = detect_csv_delimiter(sample)
    
    # 解析 CSV
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    
    rows = []
    columns = []
    
    for i, row in enumerate(reader):
        if i == 0:
            columns = list(row.keys())
        if i >= max_rows:
            break
        rows.append(dict(row))
    
    total_rows = len(rows)
    truncated = total_rows >= max_rows
    
    return {
        "columns": columns,
        "rows": rows,
        "total_rows": total_rows,
        "truncated": truncated,
    }


def parse_json(
    content: bytes,
    encoding: str = 'utf-8',
    json_path: str | None = None
) -> dict[str, Any]:
    """
    解析 JSON 文件。
    
    参数：
        json_path: JSON路径（如 "data.events" 提取嵌套数据）
    
    返回：
        {
            "data": {...} or [...],
            "is_array": bool,
            "total_items": int
        }
    """
    try:
        text = content.decode(encoding, errors='replace')
    except Exception:
        text = content.decode('utf-8', errors='replace')
    
    data = json.loads(text)
    
    # 如果指定了 JSON 路径，提取嵌套数据
    if json_path:
        for key in json_path.split('.'):
            if isinstance(data, dict):
                data = data.get(key, {})
            elif isinstance(data, list) and key.isdigit():
                data = data[int(key)]
            else:
                break
    
    is_array = isinstance(data, list)
    total_items = len(data) if is_array else 1
    
    return {
        "data": data,
        "is_array": is_array,
        "total_items": total_items,
    }


def parse_jsonl(
    content: bytes,
    encoding: str = 'utf-8',
    max_rows: int = MAX_ROWS
) -> dict[str, Any]:
    """
    解析 JSONL（每行一个JSON对象）文件。
    
    返回：
        {
            "rows": [{...}, {...}, ...],
            "total_rows": int,
            "truncated": bool
        }
    """
    try:
        text = content.decode(encoding, errors='replace')
    except Exception:
        text = content.decode('utf-8', errors='replace')
    
    rows = []
    for i, line in enumerate(text.split('\n')):
        if i >= max_rows:
            break
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    
    total_rows = len(rows)
    truncated = total_rows >= max_rows
    
    return {
        "rows": rows,
        "total_rows": total_rows,
        "truncated": truncated,
    }


def parse_txt(
    content: bytes,
    encoding: str = 'utf-8',
    log_pattern: str | None = None,
    max_lines: int = MAX_ROWS
) -> dict[str, Any]:
    """
    解析文本文件（支持日志模式匹配）。
    
    参数：
        log_pattern: 日志正则表达式模式（可选）
            示例: r'(?P<timestamp>\\S+) (?P<level>\\S+) (?P<message>.*)'
    
    返回：
        {
            "lines": ["line1", "line2", ...],  # 原始行
            "parsed_logs": [{...}, ...],       # 如果指定了log_pattern
            "total_lines": int,
            "truncated": bool
        }
    """
    try:
        text = content.decode(encoding, errors='replace')
    except Exception:
        text = content.decode('utf-8', errors='replace')
    
    lines = text.split('\n')[:max_lines]
    total_lines = len(lines)
    truncated = total_lines >= max_lines
    
    result = {
        "lines": lines,
        "total_lines": total_lines,
        "truncated": truncated,
    }
    
    # 如果指定了日志模式，尝试解析
    if log_pattern:
        pattern = re.compile(log_pattern)
        parsed_logs = []
        for line in lines:
            match = pattern.match(line)
            if match:
                parsed_logs.append(match.groupdict())
        result["parsed_logs"] = parsed_logs
    
    return result


def parse_structured_data_bytes(
    inner_path: str,
    content: bytes,
    format: str = "auto",
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    解析已读入内存的结构化数据（用于证据目录文件或 ZIP 内文件）。
    inner_path 用于格式自动检测（扩展名等）。
    """
    options = options or {}
    encoding = options.get("encoding", "utf-8")
    max_rows = options.get("max_rows", MAX_ROWS)
    file_size = len(content)

    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"文件过大: {file_size} > {MAX_FILE_SIZE}")

    if format == "auto":
        content_sample = content[:1024]
        format = detect_format(inner_path, content_sample)

    if format == "csv":
        delimiter = options.get("delimiter")
        parsed_data = parse_csv(content, encoding, delimiter, max_rows)
    elif format == "json":
        json_path = options.get("json_path")
        parsed_data = parse_json(content, encoding, json_path)
    elif format == "jsonl":
        parsed_data = parse_jsonl(content, encoding, max_rows)
    elif format == "txt":
        log_pattern = options.get("log_pattern")
        parsed_data = parse_txt(content, encoding, log_pattern, max_rows)
    else:
        raise ValueError(f"不支持的格式: {format}")

    return {
        "format": format,
        "data": parsed_data,
        "metadata": {
            "file_size": file_size,
            "encoding": encoding,
            "inner_path": inner_path,
        },
    }


def parse_structured_data(
    zip_path: Path,
    inner_path: str,
    format: str = 'auto',
    options: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    统一入口：解析 ZIP 内的结构化数据。
    
    参数：
        format: csv | json | jsonl | txt | auto
        options: 解析选项
            - delimiter: CSV分隔符
            - encoding: 编码（默认utf-8）
            - max_rows: 最大行数
            - json_path: JSON提取路径
            - log_pattern: 日志正则模式
    
    返回：
        {
            "format": str,
            "data": {...},  # 格式特定的数据
            "metadata": {
                "file_size": int,
                "encoding": str,
                ...
            }
        }
    """
    inner_norm = inner_path.replace("\\", "/")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        info = zf.getinfo(inner_norm)
        if info.file_size > MAX_FILE_SIZE:
            raise ValueError(f"文件过大: {info.file_size} > {MAX_FILE_SIZE}")
        content = zf.read(info)
    return parse_structured_data_bytes(inner_norm, content, format, options)
