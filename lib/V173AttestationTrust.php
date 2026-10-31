<?php
declare(strict_types=1);

namespace Manxing;

/** 刷新官方证明根和撤销资料；完整校验后原子替换限时策略，失败保留上次策略。 */
final class V173AttestationTrust
{
    private const ROOTS = 'https://android.googleapis.com/attestation/root';
    private const STATUS = 'https://android.googleapis.com/attestation/status';
    private const MAX_BYTES = 1048576;
    private \Closure $fetch;
    private \Closure $clock;

    public function __construct(?callable $fetch = null, ?callable $clock = null)
    {
        $this->fetch = $fetch === null ? self::download(...) : \Closure::fromCallable($fetch);
        $this->clock = $clock === null ? time(...) : \Closure::fromCallable($clock);
    }

    public function refresh(string $applicationsFile, string $policyFile): array
    {
        $applications = $this->applications($applicationsFile);
        $roots = ($this->fetch)(self::ROOTS);
        $status = ($this->fetch)(self::STATUS);
        $now = ($this->clock)();
        if ($this->age($status, $now) > 2400) {
            $status = ($this->fetch)(self::STATUS . '?v62_refresh=' . $now . '-' . bin2hex(random_bytes(4)));
            $now = ($this->clock)();
        }
        $age = $this->age($status, $now);
        if ($age > 2400) throw new \RuntimeException('官方撤销资料过旧，保留原策略');
        $rootValues = json_decode($roots['body'], true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($rootValues) || !array_is_list($rootValues) || count($rootValues) < 1 || count($rootValues) > 32)
            throw new \RuntimeException('官方证明根列表无效');
        $certificates = []; $rootHashes = [];
        foreach ($rootValues as $pem) {
            if (!is_string($pem) || strlen($pem) > 16384) throw new \RuntimeException('官方证明根格式无效');
            $certificate = @openssl_x509_read($pem);
            $parsed = $certificate === false ? false : openssl_x509_parse($certificate, false);
            $key = $certificate === false ? false : openssl_pkey_get_public($certificate);
            if ($parsed === false || $key === false || $parsed['validFrom_time_t'] > $now || $parsed['validTo_time_t'] <= $now
                || $parsed['subject'] != $parsed['issuer'] || !str_contains($parsed['extensions']['basicConstraints'] ?? '', 'CA:TRUE')
                || @openssl_x509_verify($certificate, $key) !== 1)
                throw new \RuntimeException('官方证明根的签名、期限或CA属性无效');
            if (!openssl_x509_export($certificate, $encoded)) throw new \RuntimeException('官方证明根无法编码');
            $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $encoded), true);
            if ($der === false || strlen($der) > 8192) throw new \RuntimeException('官方证明根DER格式无效');
            $digest = hash('sha256', $der);
            if (isset($rootHashes[$digest])) throw new \RuntimeException('官方证明根重复');
            $rootHashes[$digest] = true;
            $certificates[] = bin2hex($der);
        }
        $entries = json_decode($status['body'], false, 16, JSON_THROW_ON_ERROR);
        if (!$entries instanceof \stdClass || !($entries->entries ?? null) instanceof \stdClass)
            throw new \RuntimeException('官方撤销列表结构无效');
        $revoked = [];
        foreach ($entries->entries as $serial => $entry) {
            if (!preg_match('/\A[0-9a-fA-F]+\z/', (string)$serial) || !$entry instanceof \stdClass
                || !in_array($entry->status ?? null, ['REVOKED', 'SUSPENDED'], true))
                throw new \RuntimeException('官方撤销条目无效，保留原策略');
            $revoked[] = ltrim(strtolower((string)$serial), '0') ?: '0';
        }
        $revoked = array_values(array_unique($revoked)); sort($revoked, SORT_STRING);
        $policy = ['revision' => 1, 'valid_from' => $now - 300, 'valid_until' => $now + 3600 - $age,
            'root_certificates' => $certificates, 'applications' => $applications, 'revoked_serials' => $revoked];
        $bytes = json_encode($policy, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
        $this->replacePolicy($policyFile, $bytes);
        return ['passed' => true, 'refreshed_at' => gmdate('c', $now), 'valid_until' => $policy['valid_until'],
            'policy_sha256' => hash('sha256', $bytes), 'roots' => array_keys($rootHashes), 'revoked_serials' => count($revoked),
            'applications' => array_keys($applications), 'sources' => [
                'roots' => ['url' => $roots['url'], 'sha256' => hash('sha256', $roots['body'])],
                'status' => ['url' => $status['url'], 'sha256' => hash('sha256', $status['body']), 'http_age_seconds' => $age]]];
    }

    private function applications(string $file): array
    {
        $bytes = @file_get_contents($file, false, null, 0, 65537);
        if ($bytes === false || strlen($bytes) > 65536) throw new \RuntimeException('应用允许列表无法读取或过大');
        $applications = json_decode($bytes, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($applications) || $applications === [] || array_is_list($applications))
            throw new \RuntimeException('应用允许列表必须为非空对象');
        foreach ($applications as $package => $digests) {
            if (!is_string($package) || !preg_match('/\A[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\z/', $package)
                || !is_array($digests) || !array_is_list($digests) || $digests === [])
                throw new \RuntimeException('应用允许列表格式无效');
            foreach ($digests as $digest) if (!is_string($digest) || !preg_match('/\A[0-9a-f]{64}\z/', $digest))
                throw new \RuntimeException('允许的应用签名摘要无效');
        }
        return $applications;
    }

    private function age(array $response, int $now): int
    {
        $date = strtotime($response['headers']['date'] ?? '');
        $age = $response['headers']['age'] ?? '0';
        if ($date === false || $date > $now + 300 || !preg_match('/\A[0-9]{1,10}\z/', $age))
            throw new \RuntimeException('官方撤销资料缺少有效HTTP时间');
        return max(0, $now - $date, (int)$age);
    }

    private function replacePolicy(string $path, string $bytes): void
    {
        if (is_link($path)) throw new \RuntimeException('策略路径不能为符号链接');
        $directory = dirname($path);
        if (!is_dir($directory)) throw new \RuntimeException('策略目录须由部署过程提前建立');
        $temporary = tempnam($directory, '.policy-');
        if ($temporary === false) throw new \RuntimeException('无法建立策略临时文件');
        try {
            if (!@chmod($temporary, 0640) || @file_put_contents($temporary, $bytes) !== strlen($bytes))
                throw new \RuntimeException('策略临时文件写入失败');
            if (!@rename($temporary, $path)) throw new \RuntimeException('策略原子替换失败');
        } finally { if (is_file($temporary)) unlink($temporary); }
    }

    public static function download(string $url): array
    {
        if (!extension_loaded('curl')) throw new \RuntimeException('刷新官方证明资料需要PHP cURL扩展');
        $request = curl_init($url);
        if ($request === false) throw new \RuntimeException('官方证明资料HTTPS请求无法建立');
        $bytes = ''; $lines = []; $tooLarge = false;
        curl_setopt_array($request, [CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 20,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_SUPPRESS_CONNECT_HEADERS => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Accept-Encoding: identity', 'Cache-Control: no-cache, max-age=0'],
            CURLOPT_USERAGENT => 'Manxing-attestation-trust/1',
            CURLOPT_HEADERFUNCTION => static function ($request, string $line) use (&$lines): int {
                if (str_starts_with($line, 'HTTP/')) $lines = [];
                if (trim($line) !== '') $lines[] = rtrim($line, "\r\n");
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($request, string $part) use (&$bytes, &$tooLarge): int {
                if (strlen($bytes) + strlen($part) > self::MAX_BYTES) { $tooLarge = true; return 0; }
                $bytes .= $part;
                return strlen($part);
            }]);
        try {
            $complete = curl_exec($request);
            if ($tooLarge) throw new \RuntimeException('官方证明资料超过大小限制');
            if ($complete === false) throw new \RuntimeException('官方证明资料HTTPS读取失败（cURL错误' . curl_errno($request) . '）');
            if (curl_getinfo($request, CURLINFO_RESPONSE_CODE) !== 200)
                throw new \RuntimeException('官方证明资料返回非200状态或重定向');
            $headers = [];
            foreach (array_slice($lines, 1) as $line) {
                if (!str_contains($line, ':')) continue;
                [$name, $value] = explode(':', $line, 2); $name = strtolower(trim($name));
                if (in_array($name, ['date', 'age'], true) && isset($headers[$name]))
                    throw new \RuntimeException('官方证明资料包含重复时间头');
                $headers[$name] = trim($value);
            }
            return ['url' => $url, 'headers' => $headers, 'body' => $bytes];
        } finally { curl_close($request); }
    }
}
