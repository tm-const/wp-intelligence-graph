<?php
namespace WPIG\Scanner;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;
use Throwable;

if (!defined('ABSPATH')) exit;

/**
 * Collects candidate PHP files safely without loading file contents into memory.
 */
class FileCollector {
    protected array $extensions = ['php', 'phtml', 'phar'];
    protected array $skipFragments = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/cache/',
        '/cache-',
        '/.cache/',
        '/wp-content/cache/',
    ];
    protected int $maxFiles;

    public function __construct(int $maxFiles = 2500) {
        $this->maxFiles = max(100, $maxFiles);
    }

    public function collect(array $roots): array {
        $files = [];

        foreach ($roots as $root) {
            $root = wp_normalize_path((string) $root);
            if (!$root || !is_dir($root) || !is_readable($root)) {
                continue;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if (count($files) >= $this->maxFiles) {
                        break 2;
                    }

                    if (!$file->isFile() || !$file->isReadable()) {
                        continue;
                    }

                    $path = wp_normalize_path($file->getPathname());
                    if ($this->shouldSkip($path)) {
                        continue;
                    }

                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    if (!in_array($ext, $this->extensions, true)) {
                        continue;
                    }

                    $files[] = $path;
                }
            } catch (Throwable $e) {
                continue;
            }
        }

        return array_values(array_unique($files));
    }

    protected function shouldSkip(string $path): bool {
        if (defined('WPIG_PATH') && function_exists('wpig_scan_self_plugin_enabled') && !wpig_scan_self_plugin_enabled()) {
            $pluginPath = wp_normalize_path(WPIG_PATH);
            if (strpos(wp_normalize_path($path), $pluginPath) === 0) {
                return true;
            }
        }

        $normalized = '/' . trim(str_replace('\\', '/', $path), '/') . '/';
        foreach ($this->skipFragments as $fragment) {
            if (strpos($normalized, $fragment) !== false) {
                return true;
            }
        }
        return false;
    }
}
