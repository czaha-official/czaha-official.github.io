<?php
// security-detector.php

// 1. スキャン対象のディレクトリ（リポジトリのルートを指定）
$target_dir = __DIR__; 

// 2. 検知したい「サイバー攻撃を受けやすい危険な構文」の正規表現リスト
$danger_patterns = [
    'OSコマンド注入の危険' => '/\b(eval|system|exec|passthru|shell_exec)\s*\(/' ,
    '生データの出力（XSSの危険）' => '/echo\s+\$_(GET|POST|REQUEST|COOKIE)/',
    'HTML内スクリプトでの直接参照' => '/<script>.*\$_(GET|POST|REQUEST)/s',
    '安全でないSQL結合' => '/(SELECT|INSERT|UPDATE|DELETE).*FROM.*=.*\s*\.\s*\$_(GET|POST|REQUEST)/i'
];

echo "🔍 脆弱性スキャンを開始します...\n";
$has_error = false;

// 再帰的にファイルを探索
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target_dir));
foreach ($it as $file) {
    // ディレクトリ、自身（このスクリプト）、.githubフォルダ内、およびphp/html以外のファイルはスキップ
    if ($file->isDir() || 
        $file->getFilename() === 'security-detector.php' ||
        str_contains($file->getPathname(), '.github') ||
        !preg_match('/\.(php|html)$/', $file->getFilename())) {
        continue;
    }

    $filepath = $file->getPathname();
    $lines = file($filepath);

    foreach ($lines as $line_num => $line) {
        foreach ($danger_patterns as $description => $pattern) {
            if (preg_match($pattern, $line)) {
                $relative_path = str_replace(__DIR__ . '/', '', $filepath);
                echo "警告 [{$description}]\n";
                echo "ファイル: {$relative_path} (行: " . ($line_num + 1) . ")\n";
                echo "コード:   " . trim($line) . "\n\n";
                $has_error = true;
            }
        }
    }
}

// 3. 危険な構文が見つかった場合は終了コード「1」を返してActionsを落とす
if ($has_error) {
    echo "セキュリティ上の危険な構文が検出されたため、改修してください\n";
    exit(1); 
} else {
    echo " 危険な構文は見つからないか、PHPが実装されてません。このリポは安全です。\n";
    exit(0);
}
