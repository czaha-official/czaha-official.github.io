import os
import re
import json
import sys

# 1. スキャン対象（リポジトリのルート）
target_dir = os.getcwd()

# 2. 構文ごとの「ヤバさ（level）」とキュリティ規格ID（CWE）」の仕分け定義
rules_config = {
    'HTMLへの危険な生データ挿入(XSS)': {
        'pattern': r'innerHTML|outerHTML|document\.write',
        'level': 'error',
        'cwe': 'CWE-79'
    },
    '文字列をコードとして実行する関数': {
        'pattern': r'eval|setTimeout|setInterval',
        'level': 'error',
        'cwe': 'CWE-95'
    },
    'OSコマンド注入の危険': {
        'pattern': r'system|exec|passthru|shell_exec',
        'level': 'error',
        'cwe': 'CWE-78'
    },
    'インラインスクリプト内での外部データ直接参照': {
        'pattern': r'location\.search|document\.cookie|window\.name',
        'level': 'warning',
        'cwe': 'CWE-20'
    },
    '危険なイベントハンドラ構文': {
        'pattern': r'onerror|onload|onmouseover',
        'level': 'warning',
        'cwe': 'CWE-74'
    }
}

print("START: Custom Security Detector (Python)")

sarif = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "CustomSecurityDetectorPython",
                "version": "1.0.0",
                "rules": []
            }
        },
        "results": []
    }]
}

# ルール一覧をSARIFに登録
for rule_id, cfg in rules_config.items():
    sarif["runs"][0]["tool"]["driver"]["rules"].append({
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "fullDescription": {"text": f"Security Analysis Alert: {rule_id}"},
        "defaultConfiguration": {
            "level": cfg["level"]
        },
        "properties": {
            "tags": ["security", f"external/cwe/{cfg['cwe']}"]
        }
    })

critical_error_detected = False

# ファイル探索とテキスト一括スキャン（1行ずつ直接読み込む）
for root, dirs, files in os.walk(target_dir):
    # .git と .github フォルダを完全に除外
    path_parts = root.split(os.sep)
    if '.github' in path_parts or '.git' in path_parts:
        continue
        
    for file in files:
        if not file.endswith(('.php', '.html')):
            continue
            
        filepath = os.path.join(root, file)
        relative_path = os.path.relpath(filepath, target_dir).replace(os.sep, '/')
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue

        for line_num_zero_indexed, line_text in enumerate(lines):
            line_num = line_num_zero_indexed + 1
            
            for rule_id, cfg in rules_config.items():
                if re.search(cfg['pattern'], line_text, re.IGNORECASE):
                    if cfg['level'] == 'error':
                        critical_error_detected = True
                    
                    clean_text = line_text.strip()
                    print(f"FOUND: [{cfg['level']}] -> {relative_path} (Line: {line_num}) [{rule_id}]")
                    
                    # SARIFに結果を追加
                    sarif["runs"][0]["results"].append({
                        "ruleId": rule_id,
                        "message": {"text": f"[{cfg['level']}] Vulnerability detected: {rule_id} in {relative_path} (Line {line_num})"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": relative_path
                                },
                                "region": {
                                    "startLine": line_num
                                }
                            }
                        }]
                    })

# 最後に必ず results.sarif ファイルを出力する
with open("results.sarif", "w", encoding="utf-8") as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print("COMPLETE: results.sarif generated successfully.")