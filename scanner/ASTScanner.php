<?php
namespace WPIG\Scanner;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use Throwable;

if (!defined('ABSPATH')) exit;

/**
 * AST scanner powered by nikic/php-parser when installed by Composer.
 * It fails safely when dependency is not installed.
 */
class ASTScanner {
    public function available(): bool {
        return class_exists(ParserFactory::class);
    }

    public function scan(string $file): array {
        if (!$this->available()) {
            return [[
                'engine' => 'ast',
                'type' => 'php_parser_missing',
                'severity' => 'low',
                'file' => $file,
                'line' => null,
                'signature' => 'nikic/php-parser missing',
                'snippet' => '',
                'description' => 'Composer dependency nikic/php-parser is not installed. Run composer install in the plugin directory to enable AST scanning.',
            ]];
        }

        $code = @file_get_contents($file);
        if (!is_string($code) || $code === '') {
            return [];
        }

        try {
            $factory = new ParserFactory();
            if (method_exists($factory, 'createForHostVersion')) {
                $parser = $factory->createForHostVersion();
            } else {
                $parser = $factory->create(ParserFactory::PREFER_PHP7);
            }

            $ast = $parser->parse($code);
            if (!$ast) return [];

            $visitor = new class($file) extends NodeVisitorAbstract {
                public string $file;
                public array $findings = [];
                protected array $dangerous = [
                    'eval' => ['critical', 'Runtime eval execution'],
                    'assert' => ['high', 'Dynamic assertion execution'],
                    'shell_exec' => ['critical', 'Shell execution'],
                    'exec' => ['high', 'Command execution'],
                    'system' => ['critical', 'System command execution'],
                    'passthru' => ['critical', 'Command passthrough'],
                    'base64_decode' => ['high', 'Payload decoder'],
                    'gzinflate' => ['high', 'Compressed payload decoder'],
                    'str_rot13' => ['medium', 'ROT13 obfuscation'],
                    'create_function' => ['high', 'Dynamic function creation'],
                    'wp_create_user' => ['high', 'User creation abuse review'],
                    'wp_insert_user' => ['high', 'User creation abuse review'],
                    'add_role' => ['medium', 'Role creation review'],
                    'add_cap' => ['high', 'Capability grant review'],
                ];

                public function __construct(string $file) {
                    $this->file = $file;
                }

                public function enterNode(Node $node) {
                    if ($node instanceof Node\Expr\FuncCall) {
                        if ($node->name instanceof Node\Name) {
                            $name = strtolower($node->name->toString());
                            if (isset($this->dangerous[$name])) {
                                [$severity, $description] = $this->dangerous[$name];
                                $this->add('dangerous_function_call', $severity, $node, $name, $description);
                            }
                        } else {
                            $this->add('variable_function_call', 'high', $node, 'variable function call', 'Variable function calls can hide runtime execution.');
                        }
                    }

                    if ($node instanceof Node\Expr\Eval_) {
                        $this->add('eval_expression', 'critical', $node, 'eval expression', 'AST detected eval expression.');
                    }

                    if ($node instanceof Node\Expr\Include_) {
                        $expr = $node->expr;
                        if (!$expr instanceof Node\Scalar\String_) {
                            $this->add('dynamic_include', 'critical', $node, 'dynamic include/require', 'Dynamic include/require can enable file inclusion.');
                        }
                    }

                    if ($node instanceof Node\Expr\Variable && !is_string($node->name)) {
                        $this->add('variable_variable', 'high', $node, 'variable variable', 'Variable variables can hide dynamic behavior.');
                    }

                    if ($node instanceof Node\Expr\MethodCall && !$node->name instanceof Node\Identifier) {
                        $this->add('dynamic_method_call', 'medium', $node, 'dynamic method call', 'Dynamic method calls should be reviewed.');
                    }

                    if ($node instanceof Node\Expr\New_ && !$node->class instanceof Node\Name) {
                        $this->add('dynamic_class_instantiation', 'medium', $node, 'dynamic class instantiation', 'Dynamic class instantiation can hide behavior.');
                    }

                    if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower($node->name->toString()) === 'add_action') {
                        $this->inspectHook($node);
                    }
                }

                protected function inspectHook(Node\Expr\FuncCall $node): void {
                    $first = $node->args[0]->value ?? null;
                    if ($first instanceof Node\Scalar\String_) {
                        $hook = $first->value;
                        if (preg_match('/(wp_ajax_nopriv|init|template_redirect|plugins_loaded|muplugins_loaded|wp_login|authenticate|woocommerce_checkout)/i', $hook)) {
                            $this->add('suspicious_hook', 'medium', $node, $hook, 'Sensitive hook registration should be reviewed for persistence, redirects, auth abuse, or checkout skimming.');
                        }
                    }
                }

                protected function add(string $type, string $severity, Node $node, string $signature, string $description): void {
                    $this->findings[] = [
                        'engine' => 'ast',
                        'type' => $type,
                        'severity' => $severity,
                        'file' => $this->file,
                        'line' => $node->getStartLine(),
                        'signature' => $signature,
                        'snippet' => $signature,
                        'description' => $description,
                    ];
                }
            };

            $traverser = new NodeTraverser();
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            return $visitor->findings;
        } catch (Error $e) {
            return [[
                'engine' => 'ast',
                'type' => 'php_parse_error',
                'severity' => 'low',
                'file' => $file,
                'line' => $e->getStartLine(),
                'signature' => 'parse error',
                'snippet' => $e->getMessage(),
                'description' => 'AST parser could not parse this file. Scan continued.',
            ]];
        } catch (Throwable $e) {
            return [[
                'engine' => 'ast',
                'type' => 'ast_scan_error',
                'severity' => 'low',
                'file' => $file,
                'line' => null,
                'signature' => 'ast scan error',
                'snippet' => $e->getMessage(),
                'description' => 'AST scanner failed safely. Scan continued.',
            ]];
        }
    }
}
