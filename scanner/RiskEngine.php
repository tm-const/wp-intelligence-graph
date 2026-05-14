<?php
namespace WPIG\Scanner;

if (!defined('ABSPATH')) exit;

/**
 * Combines scanner findings into a deterministic 0-100 file risk score.
 */
class RiskEngine {
    protected array $weights = [
        'eval_call' => 40,
        'eval_expression' => 40,
        'shell_exec' => 35,
        'system' => 35,
        'passthru' => 35,
        'dynamic_include' => 35,
        'variable_function_call' => 30,
        'high_entropy_blob' => 30,
        'telegram_webhook' => 25,
        'discord_webhook' => 25,
        'payload_fetcher' => 25,
        'webshell_family' => 45,
        'php_upload' => 25,
    ];

    protected array $severityWeights = [
        'low' => 5,
        'medium' => 12,
        'high' => 25,
        'critical' => 40,
    ];

    public function scoreFile(string $file, array $findings): array {
        $score = 0;

        foreach ($findings as $finding) {
            $type = $finding['type'] ?? '';
            $severity = $finding['severity'] ?? 'low';
            $score += $this->weights[$type] ?? ($this->severityWeights[$severity] ?? 5);

            if (strpos($file, '/wp-content/uploads/') !== false && preg_match('/\.(php|phtml|phar)$/i', $file)) {
                $score += 25;
            }

            if (($finding['engine'] ?? '') === 'ast') {
                $score += 5;
            }

            if (($finding['engine'] ?? '') === 'entropy' && ($finding['entropy'] ?? 0) > 6) {
                $score += 10;
            }
        }

        $score = min(100, max(0, $score));

        return [
            'file' => $file,
            'score' => $score,
            'level' => $this->level($score),
        ];
    }

    public function level(int $score): string {
        if ($score >= 80) return 'Critical';
        if ($score >= 60) return 'Malware Likely';
        if ($score >= 40) return 'High Risk';
        if ($score >= 20) return 'Suspicious';
        return 'Safe';
    }
}
