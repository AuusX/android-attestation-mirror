<?php
declare(strict_types=1);

// 仅发布Google公开证书及撤销资料；签名私钥只从GitHub Actions专用Secret读取。
require __DIR__ . '/lib/V173AttestationTrust.php';
try {
    $secret = base64_decode((string)getenv('ATTESTATION_MIRROR_SIGNING_KEY'), true);
    if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)
        throw new RuntimeException('缺少镜像专用签名凭据');
    $roots = Manxing\V173AttestationTrust::download('https://android.googleapis.com/attestation/root');
    $status = Manxing\V173AttestationTrust::download('https://android.googleapis.com/attestation/status?v62_refresh=' . time() . '-' . bin2hex(random_bytes(4)));
    $now = time();
    $date = strtotime($status['headers']['date'] ?? '');
    $age = $status['headers']['age'] ?? '0';
    if ($date === false || $date > $now + 300 || !preg_match('/\A[0-9]{1,10}\z/', $age)
        || max(0, $now - $date, (int)$age) > 300) throw new RuntimeException('官方撤销资料不够新鲜，保留原快照');
    $rootValues = json_decode($roots['body'], true, 16, JSON_THROW_ON_ERROR);
    $entries = json_decode($status['body'], false, 16, JSON_THROW_ON_ERROR);
    if (!is_array($rootValues) || !array_is_list($rootValues) || count($rootValues) < 1 || count($rootValues) > 32
        || !$entries instanceof stdClass || !($entries->entries ?? null) instanceof stdClass)
        throw new RuntimeException('官方资料结构无效，保留原快照');
    $payload = json_encode(['version' => 1, 'generated_at' => $now, 'roots' => $roots, 'status' => $status],
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $signature = sodium_crypto_sign_detached("MX62-TRUST-SNAPSHOT-1\n" . $payload, $secret);
    sodium_memzero($secret);
    $encoded = json_encode(['version' => 1, 'payload' => base64_encode($payload), 'signature' => base64_encode($signature)],
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    $temporary = tempnam(__DIR__, '.snapshot-');
    if ($temporary === false) throw new RuntimeException('无法创建快照临时文件');
    try {
        if (file_put_contents($temporary, $encoded) !== strlen($encoded) || !rename($temporary, __DIR__ . '/snapshot.json'))
            throw new RuntimeException('快照写入失败，保留原文件');
    } finally { if (is_file($temporary)) unlink($temporary); }
    echo json_encode(['passed' => true, 'generated_at' => $now, 'roots' => count($rootValues),
        'revoked_serials' => count(get_object_vars($entries->entries)), 'payload_sha256' => hash('sha256', $payload)], JSON_THROW_ON_ERROR) . PHP_EOL;
} catch (Throwable $failure) {
    fwrite(STDERR, "公开证明资料刷新失败，原快照保留。\n");
    exit(1);
}
