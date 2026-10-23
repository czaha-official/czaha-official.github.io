import os
import re
import json

# 1. スキャン対象（リポジトリのルート）
target_dir = os.getcwd()

# 2. 確実に引っかけられるように正規表現パターンを徹底的にシンプル化
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
    # ----------------------------------------------------------------
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
    "$schema": "https://githubusercontent.com",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "CustomSecurityDetectorPython",
                "version": "1.3.5",
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

# ファイル探索とテキスト一括スキャン
for root, dirs, files in os.walk(target_dir):
    if '.github' in root or any(d.startswith('.') for d in root.split(os.sep)):
        continue
        
    for file in files:
        if not file.endswith(('.php', '.html')):
            continue
            
        filepath = os.path.join(root, file)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue

        relative_path = os.path.relpath(filepath, target_dir).replace(os.sep, '/')

        # 単純なキーワードマッチに変更して取りこぼしを完全に防ぐ
        for rule_id, cfg in rules_config.items():
            matches = re.finditer(cfg['pattern'], content, re.IGNORECASE)
            
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                # 前回のバグ（リスト型エラー）を確実に防ぐ安全な文字列切り出し
                lines_list = content.split('\n')
                target_line_text = lines_list[line_num - 1].strip() if line_num <= len(lines_list) else "Unknown line"
                
                sarif["runs"][0]["results"].append({
                    "ruleId": rule_id,
                    "message": {"text": f"[{cfg['level']}] Vulnerability detected: {target_line_text}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": relative_path},
                            "region": {
                                "startLine": line_num,
                                "endLine": line_num
                            }
                        }
                    }]
                })
                print(f"FOUND: [{cfg['level']}] -> {relative_path} (Line: {line_num}) [{rule_id}]")

# レポート出力
with open('results.sarif', 'w', encoding='utf-8') as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print("SUCCESS: Generated results.sarif")
