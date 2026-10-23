import os
import re
import json

# 1. スキャン対象（リポジトリのルート）
target_dir = os.getcwd()

# 2. 構文ごとの「ヤバさ（level）」と「セキュリティ規格ID（CWE）」の仕分け定義
rules_config = {
    'HTMLへの危険な生データ挿入(XSS)': {
        'pattern': r'\.(innerHTML|outerHTML|document\.write)\s*=',
        'level': 'error',
        'cwe': 'CWE-79'
    },
    '文字列をコードとして実行する関数': {
        'pattern': r'\b(eval|setTimeout|setInterval)\s*\(\s*["\']',
        'level': 'error',
        'cwe': 'CWE-95'
    },
    'OSコマンド注入の危険': {
        'pattern': r'\b(system|exec|passthru|shell_exec)\s*\(',
        'level': 'error',
        'cwe': 'CWE-78'
    },
    # ----------------------------------------------------------------
    'インラインスクリプト内での外部データ直接参照': {
        'pattern': r'<script>.*?(location\.search|document\.cookie|window\.name).*?</script>',
        'level': 'warning',
        'cwe': 'CWE-20'
    },
    '危険なイベントハンドラ構文': {
        'pattern': r'\bon(error|load|mouseover)\s*=\s*["\']',
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
                "version": "1.3.4",
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

# ファイル探索と正規表現チェック
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
            matches = re.finditer(cfg['pattern'], content, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                # 💡 修正：[0]を指定して1行目を安全に取り出し、リスト型エラーを解消
                full_matched_text = match.group(0)
                first_line_text = full_matched_text.split('\n')[0].strip()
                
                sarif["runs"][0]["results"].append({
                    "ruleId": rule_id,
                    "message": {"text": f"[{cfg['level']}] Vulnerability detected: {first_line_text}"},
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
