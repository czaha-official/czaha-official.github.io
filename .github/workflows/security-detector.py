import os
import re
import json

# 1. スキャン対象（リポジトリのルート）
target_dir = os.getcwd()

# 2. 構文ごとの「ヤバさ（level）」と「セキュリティ規格ID（CWE）」の仕分け定義
rules_config = {
    'HTMLへの危険な生データ挿入(XSS)': {
        'pattern': r'\.(innerHTML|outerHTML|document\.write)\s*=',
        'level': 'error',       # 深刻：Copilotが自動で修正パッチ(PR)を作る
        'cwe': 'CWE-79'
    },
    '文字列をコードとして実行する関数': {
        'pattern': r'\b(eval|setTimeout|setInterval)\s*\(\s*["\']',
        'level': 'error',       # 深刻
        'cwe': 'CWE-95'
    },
    'OSコマンド注入の危険': {
        'pattern': r'\b(system|exec|passthru|shell_exec)\s*\(',
        'level': 'error',       # 深刻
        'cwe': 'CWE-78'
    },
    # ----------------------------------------------------------------
    'インラインスクリプト内での外部データ直接参照': {
        'pattern': r'<script>.*(location\.search|document\.cookie|window\.name)',
        'level': 'warning',     # 軽い：Copilot経由でユーザーに選択肢を選ばせる（トークン節約）
        'cwe': 'CWE-20'
    },
    '危険なイベントハンドラ構文': {
        'pattern': r'\bon(error|load|mouseover)\s*=\s*["\']',
        'level': 'warning',     # 軽い
        'cwe': 'CWE-74'
    }
}

print("🔍 脆弱性スキャンを開始します（Python・ヤバさ判定修正版）...")

sarif = {
    "$schema": "https://githubusercontent.com",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "CustomSecurityDetectorPython",
                "version": "1.3.1",
                "rules": []
            }
        },
        "results": []
    }]
}

#  修正：sarif["runs"][0] を正しく指定して階層のバグを解消
for rule_id, cfg in rules_config.items():
    sarif["runs"][0]["tool"]["driver"]["rules"].append({
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "fullDescription": {"text": f"セキュリティ分析アラート: {rule_id}"},
        "defaultConfiguration": {
            "level": cfg["level"]
        },
        "properties": {
            "tags": ["security", f"external/cwe/{cfg['cwe']}"]
        }
    })

# ファイル探索と正規表現チェック
for root, dirs, files in os.walk(target_dir):
    # .githubなどの管理フォルダ内は除外して無限ループ防止
    if '.github' in root or any(d.startswith('.') for d in root.split(os.sep)):
        continue
        
    for file in files:
        if not file.endswith(('.php', '.html')):
            continue
            
        filepath = os.path.join(root, file)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue

        for line_num, line in enumerate(lines):
            for rule_id, cfg in rules_config.items():
                if re.search(cfg['pattern'], line, re.IGNORECASE):
                    relative_path = os.path.relpath(filepath, target_dir)
                    
                    #  修正：ここも同様に sarif["runs"][0] に修正
                    sarif["runs"][0]["results"].append({
                        "ruleId": rule_id,
                        "message": {"text": f"[{cfg['level']}] 危険な構文を検出しました: {line.strip()}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": relative_path.replace(os.sep, '/')},
                                "region": {
                                    "startLine": line_num + 1,
                                    "endLine": line_num + 1
                                }
                            }
                        }]
                    })
                    print(f" [{cfg['level']}] 発見 -> {relative_path} (行: {line_num + 1}) [{rule_id}]")

# レポート出力
with open('results.sarif', 'w', encoding='utf-8') as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print("レポートを出力しました (results.sarif)")
