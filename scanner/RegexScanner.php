<?php
namespace WPIG\Scanner;

if (!defined('ABSPATH')) exit;

/**
 * Fast signature scanner for high-signal malware indicators.
 */
class RegexScanner {
    protected array $patterns = [];

    public function __construct() {
        $this->patterns = [
            'eval_call' => ['/eval\s*\(/i', 'critical', 'eval() runtime execution'],
            'base64_decode' => ['/base64_decode\s*\(/i', 'high', 'base64_decode() payload decoder'],
            'shell_exec' => ['/shell_exec\s*\(/i', 'critical', 'shell_exec() command execution'],
            'exec' => ['/\bexec\s*\(/i', 'high', 'exec() command execution'],
            'system' => ['/\bsystem\s*\(/i', 'critical', 'system() command execution'],
            'passthru' => ['/passthru\s*\(/i', 'critical', 'passthru() command execution'],
            'assert_call' => ['/assert\s*\(/i', 'high', 'assert() dynamic execution'],
            'preg_replace_e' => ['/preg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]/i', 'critical', 'preg_replace /e execution modifier'],
            'gzinflate' => ['/gzinflate\s*\(/i', 'high', 'gzinflate() compressed payload'],
            'str_rot13' => ['/str_rot13\s*\(/i', 'medium', 'ROT13 obfuscation'],
            'create_function' => ['/create_function\s*\(/i', 'high', 'create_function() dynamic code'],
            'telegram_webhook' => ['/api\.telegram\.org\/bot/i', 'high', 'Telegram bot callback/webhook'],
            'discord_webhook' => ['/discord(?:app)?\.com\/api\/webhooks/i', 'high', 'Discord webhook callback'],
            'payload_fetcher' => ['/(raw\.githubusercontent\.com|pastebin\.com|gist\.githubusercontent\.com|bitbucket\.org|gitlab\.com\/.*\/raw)/i', 'high', 'Remote payload fetcher domain'],
            'hidden_iframe' => ['/<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'"]?0|height\s*=\s*[\'"]?0)/i', 'high', 'Hidden iframe injection'],
            'js_redirect' => ['/(window\.location|document\.location|location\.href)\s*=/i', 'medium', 'JavaScript redirect pattern'],
            'char_obfuscation' => ['/(chr\s*\(|hex2bin\s*\(|pack\s*\(|strrev\s*\()/i', 'medium', 'String/character obfuscation'],
            'webshell_family' => ['/(WSO|FilesMan|IndoXploit|r57shell|c99shell|Mini Shell|b374k)/i', 'critical', 'Known webshell family string'],
            'ai_prompt_injection' => ['/(ignore previous instructions|system prompt|jailbreak|prompt injection|api\.openai\.com|api\.anthropic\.com)/i', 'medium', 'AI-era prompt/API risk string'],
        ];
    }

    public function scan(string $file): array {
        if (!is_readable($file)) {
            return [];
        }

        $findings = [];
        $lines = @file($file);
        if (!is_array($lines)) {
            return [];
        }

        foreach ($lines as $lineNumber => $line) {
            foreach ($this->patterns as $type => $config) {
                [$pattern, $severity, $description] = $config;
                if (preg_match($pattern, $line, $match)) {
                    $findings[] = [
                        'engine' => 'regex',
                        'type' => $type,
                        'severity' => $severity,
                        'file' => $file,
                        'line' => $lineNumber + 1,
                        'signature' => $match[0] ?? $type,
                        'snippet' => trim(substr($line, 0, 300)),
                        'description' => $description,
                    ];
                }
            }
        }

        return $findings;
    }
}
