<?php
namespace WPIG\Scanner;

if (!defined('ABSPATH')) exit;

/**
 * Orchestrates FileCollector -> RegexScanner -> ASTScanner -> EntropyScanner -> RiskEngine.
 */
class ScanManager {
    protected FileCollector $collector;
    protected RegexScanner $regex;
    protected ASTScanner $ast;
    protected EntropyScanner $entropy;
    protected RiskEngine $risk;

    public function __construct(int $maxFiles = 2500) {
        $this->collector = new FileCollector($maxFiles);
        $this->regex = new RegexScanner();
        $this->ast = new ASTScanner();
        $this->entropy = new EntropyScanner();
        $this->risk = new RiskEngine();
    }

    public function run(array $roots): array {
        $files = $this->collector->collect($roots);
        $findings = [];
        $riskScores = [];
        $byFile = [];

        foreach ($files as $file) {
            $fileFindings = [];

            $fileFindings = array_merge($fileFindings, $this->regex->scan($file));
            $fileFindings = array_merge($fileFindings, $this->ast->scan($file));
            $fileFindings = array_merge($fileFindings, $this->entropy->scan($file));

            if (!empty($fileFindings)) {
                $byFile[$file] = $fileFindings;
                $findings = array_merge($findings, $fileFindings);
                $riskScores[$file] = $this->risk->scoreFile($file, $fileFindings);
            }
        }

        return [
            'scanner' => 'advanced',
            'files' => count($files),
            'findings' => count($findings),
            'parser_available' => $this->ast->available(),
            'results' => $findings,
            'by_file' => $byFile,
            'risk_scores' => array_values($riskScores),
        ];
    }
}
