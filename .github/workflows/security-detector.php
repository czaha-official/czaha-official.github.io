<?php
// security-detector.php

$target_dir = getcwd(); 
$danger_patterns = [
    'OSコマンド注入の危険' => '/\b(eval|system|exec|passthru|shell_exec)\s*\(/',
    '生データの出力（XSSの危険）' => '/echo\s+\$_(GET|POST|REQUEST|COOKIE)/',
    'HTML内スクリプトでの直接参照' => '/<script>.*\$_(GET|POST|REQUEST)/s',
    '安全でないSQL結合' => '/(SELECT|INSERT|UPDATE|DELETE).*FROM.*=.*\s*\.\s*\$_(GET|POST|REQUEST)/i'
];

echo "脆弱性スキャンを開始します（GitHub Security連携版）...\n";

// SARIFフォーマットの基礎構造を定義
$sarif = [
    '$schema' => 'https://githubusercontent.com',
    'version' => '2.1.0',
    'runs' => [[
        'tool' => [
            'driver' => [
                'name' => 'CustomPHPSecurityDetector',
                'version' => '1.0.0',
                'rules' => []
            ]
        ],
        'results' => []
    ]]
];

// ルール定義をSARIFに追加
foreach ($danger_patterns as $id => $pattern) {
    $sarif['runs'][0]['tool']['driver']['rules'][] = [
        'id' => $id,
        'shortDescription' => ['text' => $id],
        'fullDescription' => ['text' => "サイバー攻撃の標的になりやすい危険な構文： {$id}"],
        'defaultConfiguration' => ['level' => 'error']
    ];
}

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target_dir));
foreach ($it as $file) {
    if ($file->isDir() || 
        $file->getFilename() === 'security-detector.php' ||
        str_contains($file->getPathname(), '.github') ||
        !preg_match('/\.(php|html)$/', $file->getFilename())) {
        continue;
    }

    $filepath = $file->getPathname();
    $lines = file($filepath);

    foreach ($lines as $line_num => $line) {
        foreach ($danger_patterns as $id => $pattern) {
            if (preg_match($pattern, $line)) {
                $relative_path = str_replace(__DIR__ . '/', '', $filepath);
                
                // GitHubのセキュリティタブに表示するアラート情報を追加
                $sarif['runs'][0]['results'][] = [
                    'ruleId' => $id,
                    'message' => ['text' => "危険な構文が検出されました: " . trim($line)],
                    'locations' => [[
                        'physicalLocation' => [
                            'artifactLocation' => ['uri' => $relative_path],
                            'region' => [
                                'startLine' => $line_num + 1,
                                'endLine' => $line_num + 1
                            ]
                        ]
                    ]]
                ];
                echo "警告 [{$id}] 発見 -> {$relative_path} (行: " . ($line_num + 1) . ")\n";
            }
        }
    }
}

// 結果をSARIF形式のJSONファイルとして書き出し
file_put_contents('results.sarif', json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "レポートを出力しました (results.sarif)\n";
