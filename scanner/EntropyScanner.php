<?php
namespace WPIG\Scanner;

if (!defined('ABSPATH')) exit;

/**
 * Shannon entropy scanner for encoded/encrypted/compressed blobs.
 */
class EntropyScanner {
    protected int $maxBytes;

    public function __construct(int $maxBytes = 800000) {
        $this->maxBytes = max(50000, $maxBytes);
    }

    public function scan(string $file): array {
        if (!is_readable($file)) {
            return [];
        }

        $contents = @file_get_contents($file, false, null, 0, $this->maxBytes);
        if (!is_string($contents) || $contents === '') {
            return [];
        }

        $findings = [];
        $chunks = $this->extractCandidateStrings($contents);
        foreach ($chunks as $chunk) {
            $entropy = $this->entropy($chunk['value']);
            $severity = $this->severity($entropy);
            if ($severity === 'normal') {
                continue;
            }

            $findings[] = [
                'engine' => 'entropy',
                'type' => 'high_entropy_blob',
                'severity' => $severity,
                'file' => $file,
                'line' => $chunk['line'],
                'signature' => 'entropy ' . round($entropy, 2),
                'snippet' => substr($chunk['value'], 0, 180),
                'description' => 'High entropy string/blob may indicate encoded, compressed, encrypted, or polymorphic payload.',
                'entropy' => round($entropy, 4),
            ];
        }

        return $findings;
    }

    protected function extractCandidateStrings(string $contents): array {
        $candidates = [];

        if (preg_match_all('/[A-Za-z0-9+\/=]{120,}/', $contents, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $candidates[] = [
                    'value' => $match[0],
                    'line' => substr_count(substr($contents, 0, $match[1]), "\n") + 1,
                ];
            }
        }

        if (preg_match_all('/[a-f0-9]{160,}/i', $contents, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $candidates[] = [
                    'value' => $match[0],
                    'line' => substr_count(substr($contents, 0, $match[1]), "\n") + 1,
                ];
            }
        }

        return array_slice($candidates, 0, 25);
    }

    protected function entropy(string $data): float {
        $length = strlen($data);
        if ($length === 0) return 0.0;

        $freq = count_chars($data, 1);
        $entropy = 0.0;

        foreach ($freq as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    protected function severity(float $entropy): string {
        if ($entropy >= 6.0) return 'critical';
        if ($entropy >= 5.0) return 'high';
        if ($entropy >= 4.0) return 'medium';
        return 'normal';
    }
}
