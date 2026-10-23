import os
import re
import json
import sys  # 💡 修正：スクリプトエラー（終了コード）を吐き出すために追加

# 1. スキャン対象（リポジトリのルート）
target_dir = os.getcwd()

# 2. 構文ごとの「ヤバさ（level）」と「セキュリティ規格ID（CWE）」の仕分け定義
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
                "version": "1.3.7",
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

# 💡 深刻なエラー（error）を見つけたかどうかを記憶するフラグ
critical_error_detected = False

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

        for rule_id, cfg in rules_config.items():
            matches = re.finditer(cfg['pattern'], content, re.IGNORECASE)
            
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                lines_list = content.split('\n')
                target_line_text = lines_list[line_num - 1].strip() if line_num <= len(lines_list) else "Unknown line"
                
                # 💡 もし検知したバグのレベルが 'error'（深刻）なら、フラグをONにする
                if cfg['level'] == 'error':
                    critical_error_detected = True
                
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

# レポート出力（エラーで落ちる前に必ずSARIFファイルは書き出す）
with open('results.sarif', 'w', encoding='utf-8') as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print("SUCCESS: Generated results.sarif")

#  修正：深刻なバグ（error）が1件でもあれば、強制的にスクリプトエラー（終了コード1）をはいてActionsを落とす
if critical_error_detected:
    print("[ FAILD ] Severe security vulnerabilities found. Blocking build.")
    sys.exit(1)
else:
    print("[ OK ]: No critical errors found.")
    sys.exit(0)
