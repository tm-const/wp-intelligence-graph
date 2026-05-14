<?php
/**
 * Plugin Name: WP Intelligence Graph
 * Description: WordPress-native intelligence graph with malware scanner, enhanced media editor workflow, media scanner, exposure scanner, server installer guidance, scanner-specific findings filters, code quality scanner, custom tables, findings, graph isolation, filters, and Cytoscape.js admin viewer.
 * Version: 0.8.4-modular.32
 * Author: Manny Quintanilla
 * License: GPL-2.0-or-later
 */

if (!defined('ABSPATH')) exit;

define('WPIG_VERSION', '0.8.4-modular.32');
define('WPIG_URL', plugin_dir_url(__FILE__));
define('WPIG_PATH', plugin_dir_path(__FILE__));


// Optional Composer autoload for nikic/php-parser.
if (file_exists(WPIG_PATH . 'vendor/autoload.php')) {
    require_once WPIG_PATH . 'vendor/autoload.php';
}

// Modular scanner engine.
foreach (['FileCollector.php','RegexScanner.php','ASTScanner.php','EntropyScanner.php','RiskEngine.php','ScanManager.php'] as $wpig_scanner_file) {
    $wpig_scanner_path = WPIG_PATH . 'scanner/' . $wpig_scanner_file;
    if (file_exists($wpig_scanner_path)) {
        require_once $wpig_scanner_path;
    }
}

register_activation_hook(__FILE__, 'wpig_activate');

function wpig_tables() {
    global $wpdb;
    return [
        'nodes' => $wpdb->prefix . 'wpig_nodes',
        'edges' => $wpdb->prefix . 'wpig_edges',
        'findings' => $wpdb->prefix . 'wpig_findings',
        'scans' => $wpdb->prefix . 'wpig_scans',
    ];
}


function wpig_default_settings() {
    return [
        'malware_default_engines' => ['builtin'],
        'malware_default_paths' => ['plugins', 'themes', 'uploads'],
        'quality_default_paths' => ['plugins', 'themes'],
        'large_function_lines' => 120,
        'large_media_kb' => 500,
        'large_image_dimension' => 2000,
        'scan_file_limit' => 2200,
        'vendor_cdn_notice' => true,
    ];
}

function wpig_get_settings() {
    $saved = get_option('wpig_settings', []);
    if (!is_array($saved)) $saved = [];
    return array_merge(wpig_default_settings(), $saved);
}

function wpig_resource_install_commands() {
    return [
        'debian_ubuntu' => [
            'label' => 'Debian / Ubuntu',
            'commands' => [
                'sudo apt update',
                'sudo apt install yara clamav clamav-daemon',
                'sudo freshclam',
                '# Maldet is usually installed manually from rfxn.com; only install it if you manage the server.'
            ],
        ],
        'redhat_centos' => [
            'label' => 'RHEL / CentOS / AlmaLinux',
            'commands' => [
                'sudo dnf install epel-release',
                'sudo dnf install yara clamav clamav-update',
                'sudo freshclam',
                '# Maldet is usually installed manually from rfxn.com; only install it if you manage the server.'
            ],
        ],
        'macos' => [
            'label' => 'macOS / Local Dev',
            'commands' => [
                'brew install yara clamav',
                'freshclam'
            ],
        ],
    ];
}


function wpig_activate() {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $t = wpig_tables();
    $charset = $wpdb->get_charset_collate();

    dbDelta("CREATE TABLE {$t['nodes']} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        uid VARCHAR(191) NOT NULL,
        node_type VARCHAR(64) NOT NULL,
        label VARCHAR(255) NOT NULL,
        object_id BIGINT UNSIGNED NULL,
        object_type VARCHAR(64) NULL,
        url TEXT NULL,
        properties LONGTEXT NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uid (uid),
        KEY node_type (node_type)
    ) $charset;");

    dbDelta("CREATE TABLE {$t['edges']} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        uid VARCHAR(191) NOT NULL,
        source_uid VARCHAR(191) NOT NULL,
        target_uid VARCHAR(191) NOT NULL,
        edge_type VARCHAR(64) NOT NULL,
        label VARCHAR(255) NULL,
        weight FLOAT DEFAULT 1,
        properties LONGTEXT NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uid (uid),
        KEY source_uid (source_uid),
        KEY target_uid (target_uid),
        KEY edge_type (edge_type)
    ) $charset;");

    dbDelta("CREATE TABLE {$t['findings']} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        uid VARCHAR(191) NOT NULL,
        finding_type VARCHAR(64) NOT NULL,
        severity VARCHAR(32) NOT NULL,
        score INT UNSIGNED DEFAULT 0,
        title VARCHAR(255) NOT NULL,
        description TEXT NULL,
        source_type VARCHAR(64) NULL,
        source_uid VARCHAR(191) NULL,
        source_file TEXT NULL,
        line_number INT UNSIGNED NULL,
        matched_pattern VARCHAR(255) NULL,
        matched_snippet TEXT NULL,
        owner_type VARCHAR(64) NULL,
        owner_name VARCHAR(255) NULL,
        evidence LONGTEXT NULL,
        status VARCHAR(32) DEFAULT 'open',
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uid (uid),
        KEY finding_type (finding_type),
        KEY severity (severity),
        KEY source_uid (source_uid),
        KEY status (status)
    ) $charset;");

    dbDelta("CREATE TABLE {$t['scans']} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        scan_type VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        summary LONGTEXT NULL,
        started_at DATETIME NOT NULL,
        finished_at DATETIME NULL,
        PRIMARY KEY (id),
        KEY scan_type (scan_type),
        KEY status (status)
    ) $charset;");

    if (!get_option('wpig_settings')) {
        update_option('wpig_settings', wpig_default_settings(), false);
    }
}

function wpig_safe_exec_available() {
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    return function_exists('shell_exec') && !in_array('shell_exec', $disabled, true);
}

function wpig_command_exists($command) {
    if (!wpig_safe_exec_available()) return false;
    $command = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $command);
    $result = @shell_exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null');
    return !empty($result);
}

function wpig_scanner_availability() {
    return [
        'builtin' => ['name'=>'Built-in Indicator Scanner','available'=>true,'description'=>'Pattern-based PHP, JS, content, uploads, and wp_options indicator scan.'],
        'code_quality' => ['name'=>'Code Quality Scanner','available'=>function_exists('token_get_all'),'description'=>'Uses PHP token_get_all() to detect duplicate functions, classes, methods, repeated bodies, and large functions.'],
        'advanced' => ['name'=>'Advanced Modular Engine','available'=>class_exists('WPIG\\Scanner\\ScanManager'),'description'=>'Runs FileCollector, RegexScanner, ASTScanner, EntropyScanner, and RiskEngine. AST requires Composer dependency nikic/php-parser.'],
        'php_parser' => ['name'=>'nikic/php-parser','available'=>class_exists('PhpParser\\ParserFactory'),'description'=>'Required for AST scanning. Run composer install in the plugin folder if unavailable.'],
        'yara' => ['name'=>'YARA','available'=>wpig_command_exists('yara'),'description'=>'Rule-based malware scanning if the yara command is installed on the server.'],
        'clamav' => ['name'=>'ClamAV','available'=>wpig_command_exists('clamscan'),'description'=>'Antivirus signature scanning if clamscan is installed on the server.'],
        'maldet' => ['name'=>'Linux Malware Detect / Maldet','available'=>wpig_command_exists('maldet'),'description'=>'Linux server malware scanner if maldet is installed on the server.'],
        'shell_exec' => ['name'=>'Server Command Execution','available'=>wpig_safe_exec_available(),'description'=>'Required for YARA, ClamAV, and Maldet integrations. Built-in and code quality scanners work without it.'],
    ];
}

function wpig_json($v) { return wp_json_encode($v); }

function wpig_upsert_node($uid, $type, $label, $args = []) {
    global $wpdb; $t = wpig_tables(); $now = current_time('mysql');
    $data = [
        'uid' => sanitize_text_field($uid),
        'node_type' => sanitize_key($type),
        'label' => sanitize_text_field(wp_strip_all_tags($label)),
        'object_id' => isset($args['object_id']) ? absint($args['object_id']) : null,
        'object_type' => isset($args['object_type']) ? sanitize_key($args['object_type']) : null,
        'url' => isset($args['url']) ? esc_url_raw($args['url']) : null,
        'properties' => isset($args['properties']) ? wpig_json($args['properties']) : null,
        'updated_at' => $now,
    ];
    $id = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$t['nodes']} WHERE uid=%s", $uid));
    if ($id) { $wpdb->update($t['nodes'], $data, ['uid'=>$uid]); return (int)$id; }
    $data['created_at'] = $now; $wpdb->insert($t['nodes'], $data); return (int)$wpdb->insert_id;
}

function wpig_upsert_edge($source, $target, $type, $args = []) {
    global $wpdb; $t = wpig_tables(); $now = current_time('mysql');
    $uid = $args['uid'] ?? md5($source.'|'.$type.'|'.$target);
    $data = [
        'uid' => sanitize_text_field($uid),
        'source_uid' => sanitize_text_field($source),
        'target_uid' => sanitize_text_field($target),
        'edge_type' => sanitize_key($type),
        'label' => isset($args['label']) ? sanitize_text_field($args['label']) : sanitize_key($type),
        'weight' => isset($args['weight']) ? floatval($args['weight']) : 1,
        'properties' => isset($args['properties']) ? wpig_json($args['properties']) : null,
        'updated_at' => $now,
    ];
    $id = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$t['edges']} WHERE uid=%s", $uid));
    if ($id) { $wpdb->update($t['edges'], $data, ['uid'=>$uid]); return (int)$id; }
    $data['created_at'] = $now; $wpdb->insert($t['edges'], $data); return (int)$wpdb->insert_id;
}

function wpig_add_finding($uid, $type, $severity, $score, $title, $args = []) {
    global $wpdb; $t = wpig_tables(); $now = current_time('mysql');
    $data = [
        'uid' => sanitize_text_field($uid),
        'finding_type' => sanitize_key($type),
        'severity' => sanitize_key($severity),
        'score' => absint($score),
        'title' => sanitize_text_field($title),
        'description' => isset($args['description']) ? sanitize_textarea_field($args['description']) : null,
        'source_type' => isset($args['source_type']) ? sanitize_key($args['source_type']) : null,
        'source_uid' => isset($args['source_uid']) ? sanitize_text_field($args['source_uid']) : null,
        'source_file' => isset($args['source_file']) ? sanitize_text_field($args['source_file']) : null,
        'line_number' => isset($args['line_number']) ? absint($args['line_number']) : null,
        'matched_pattern' => isset($args['matched_pattern']) ? sanitize_text_field($args['matched_pattern']) : null,
        'matched_snippet' => isset($args['matched_snippet']) ? sanitize_textarea_field($args['matched_snippet']) : null,
        'owner_type' => isset($args['owner_type']) ? sanitize_key($args['owner_type']) : null,
        'owner_name' => isset($args['owner_name']) ? sanitize_text_field($args['owner_name']) : null,
        'evidence' => isset($args['evidence']) ? wpig_json($args['evidence']) : null,
        'status' => 'open',
        'updated_at' => $now,
    ];
    $id = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$t['findings']} WHERE uid=%s", $uid));
    if ($id) { $wpdb->update($t['findings'], $data, ['uid'=>$uid]); return (int)$id; }
    $data['created_at'] = $now; $wpdb->insert($t['findings'], $data); return (int)$wpdb->insert_id;
}

function wpig_reset_graph() {
    global $wpdb; $t = wpig_tables();
    $wpdb->query("TRUNCATE TABLE {$t['nodes']}");
    $wpdb->query("TRUNCATE TABLE {$t['edges']}");
    $wpdb->query("TRUNCATE TABLE {$t['findings']}");
}

function wpig_file_owner($relative) {
    $parts = explode('/', $relative);
    if (($parts[0] ?? '') === 'wp-content' && ($parts[1] ?? '') === 'plugins' && !empty($parts[2])) return ['type'=>'plugin','slug'=>$parts[2],'name'=>$parts[2],'uid'=>'plugin:'.$parts[2]];
    if (($parts[0] ?? '') === 'wp-content' && ($parts[1] ?? '') === 'themes' && !empty($parts[2])) return ['type'=>'theme','slug'=>$parts[2],'name'=>$parts[2],'uid'=>'theme:'.$parts[2]];
    if (strpos($relative, 'wp-content/uploads/') === 0) return ['type'=>'uploads','slug'=>'uploads','name'=>'Uploads','uid'=>'area:uploads'];
    if (strpos($relative, 'wp-content/mu-plugins/') === 0) return ['type'=>'mu_plugin','slug'=>'mu-plugins','name'=>'MU Plugins','uid'=>'area:mu-plugins'];
    return ['type'=>'file','slug'=>'','name'=>'','uid'=>''];
}

function wpig_post_type_label($type) {
    if ($type === 'post') return 'post';
    if ($type === 'page') return 'page';
    return 'cpt_' . sanitize_key($type);
}

function wpig_scan_paths_from_request($paths = []) {
    $available = [
        'plugins' => WP_CONTENT_DIR . '/plugins',
        'themes' => WP_CONTENT_DIR . '/themes',
        'uploads' => WP_CONTENT_DIR . '/uploads',
        'mu_plugins' => WPMU_PLUGIN_DIR,
        'wp_content' => WP_CONTENT_DIR,
        'root' => ABSPATH,
        'core' => ABSPATH,
    ];

    $selected = [];
    foreach ((array) $paths as $path) {
        $key = sanitize_key($path);
        if (!isset($available[$key])) continue;
        if ($key === 'core') {
            if (is_dir(ABSPATH . 'wp-admin')) $selected['wp_admin'] = ABSPATH . 'wp-admin';
            if (is_dir(ABSPATH . 'wp-includes')) $selected['wp_includes'] = ABSPATH . 'wp-includes';
            continue;
        }
        if (is_dir($available[$key])) {
            $selected[$key] = $available[$key];
        }
    }

    if (!$selected) {
        foreach (['plugins','themes','uploads'] as $key) {
            if (is_dir($available[$key])) $selected[$key] = $available[$key];
        }
    }

    return $selected;
}

function wpig_start_scan_row($type) {
    global $wpdb; $t = wpig_tables();
    $wpdb->insert($t['scans'], ['scan_type'=>sanitize_key($type),'status'=>'running','started_at'=>current_time('mysql')]);
    return (int) $wpdb->insert_id;
}

function wpig_finish_scan_row($id, $summary, $status = 'completed') {
    global $wpdb; $t = wpig_tables();
    $wpdb->update($t['scans'], ['status'=>sanitize_key($status),'summary'=>wp_json_encode($summary),'finished_at'=>current_time('mysql')], ['id'=>absint($id)]);
}

function wpig_record_file_finding($summary, $file_uid, $relative, $owner, $key, $severity, $score, $title, $indicator, $line, $snippet, $description, $scanner = 'builtin') {
    $fuid = 'finding:' . sanitize_key($scanner) . ':' . md5($relative . ':' . $key . ':' . $line . ':' . $snippet);
    $iuid = 'indicator:' . sanitize_title($indicator);
    wpig_upsert_node($iuid, $scanner === 'code_quality' ? 'refactor_opportunity' : 'malware_indicator', $indicator, ['properties'=>['indicator_key'=>$key,'scanner'=>$scanner]]);
    wpig_add_finding($fuid, $scanner === 'builtin' ? 'file_security' : $scanner . '_scan', $severity, $score, $title, [
        'description'=>$description,
        'source_type'=>'file','source_uid'=>$file_uid,'source_file'=>$relative,'line_number'=>$line,
        'matched_pattern'=>$key,'matched_snippet'=>$snippet,'owner_type'=>$owner['type'],'owner_name'=>$owner['name'],
        'evidence'=>['path'=>$relative,'line_number'=>$line,'snippet'=>$snippet,'owner'=>$owner,'scanner'=>$scanner,'editor_url'=>wpig_file_editor_url($relative, $owner)],
    ]);
    wpig_upsert_node($fuid, 'finding', $title, ['properties'=>['severity'=>$severity,'score'=>$score,'finding_type'=>$scanner === 'builtin' ? 'file_security' : $scanner . '_scan','scanner'=>$scanner]]);
    wpig_upsert_edge($file_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
    wpig_upsert_edge($fuid, $iuid, 'classified_as', ['label'=>'Classified As']);
    if (!empty($owner['uid'])) wpig_upsert_edge($owner['uid'], $fuid, 'has_finding', ['label'=>'Finding']);
    $summary['findings']++;
    return $summary;
}

function wpig_builtin_malware_scan($scan_paths = []) {
    wpig_cleanup_self_plugin_findings();
    $summary = ['scanner'=>'builtin','files'=>0,'findings'=>0,'paths'=>array_keys($scan_paths)];
    $patterns = [
        'eval('=>['critical',95,'Executable Eval'], 'base64_decode('=>['high',86,'Base64 Decode'], 'gzinflate('=>['high',84,'Compressed Payload'],
        'shell_exec('=>['critical',94,'Shell Execution'], 'passthru('=>['critical',94,'Shell Execution'], 'system('=>['critical',94,'System Execution'],
        'exec('=>['high',82,'Command Execution'], 'assert('=>['high',80,'Dynamic Assertion'],
        'str_rot13('=>['medium',70,'String Rotation Obfuscation'], 'create_function('=>['high',82,'Dynamic Function Creation'],
        'chr('=>['medium',65,'Character Obfuscation'],
        'pack('=>['medium',66,'Packed Payload Pattern'],
        'unserialize('=>['medium',64,'Unsafe Deserialization Review'],
        'rawurldecode('=>['low',45,'Encoded Payload Review'],
        'urldecode('=>['low',45,'Encoded Payload Review'],
        'hex2bin('=>['medium',68,'Hex Payload Decode'],
        'strrev('=>['low',44,'String Reversal Obfuscation'],
        'preg_replace('=>['medium',60,'Dynamic Regex Review'],
        'ReflectionFunction'=>['medium',66,'Reflection Function Review'],
        'ReflectionClass'=>['medium',66,'Reflection Class Review'],
        'openssl_decrypt('=>['medium',70,'Encrypted Payload Review'],
        'mcrypt_decrypt('=>['high',78,'Legacy Encrypted Payload Review'],
        'xor'=>['low',42,'XOR Pattern Review'],
        'ob_start('=>['low',45,'Output Buffering Review'],
        'fsockopen('=>['medium',70,'Socket / C2 Review'],
        'stream_socket_client('=>['medium',72,'Socket / C2 Review'],
        'base64_encode('=>['low',45,'Payload Encoder Review'],
        'wp_create_user('=>['high',82,'User Creation Review'],
        'wp_insert_user('=>['high',82,'User Creation Review'],
        'set_user_role('=>['high',82,'Capability Grant Review'],
        'add_role('=>['medium',68,'Role Creation Review'],
        'add_cap('=>['high',84,'Capability Grant Review'],
        'wp_mail('=>['medium',58,'Email Interception / Exfil Review'],
    ];
    foreach ($scan_paths as $root) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $count = 0;
        foreach ($it as $file) {
            if ($count >= 2200) break;
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            $relative = str_replace(ABSPATH, '', $path);
            if (wpig_should_skip_self_scan_file($relative)) continue;
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php','js','html','htm'], true)) continue;
            $count++; $summary['files']++;
            $owner = wpig_file_owner($relative);
            $file_uid = 'file:' . md5($relative);
            wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>[
                'path'=>$relative,'directory'=>dirname($relative),'extension'=>$ext,'modified'=>gmdate('c',$file->getMTime()),
                'size'=>$file->getSize(),'sha1'=>@sha1_file($path),'owner_type'=>$owner['type'],'owner_name'=>$owner['name'],
            ]]);
            if (!empty($owner['uid'])) {
                wpig_upsert_node($owner['uid'], $owner['type'], $owner['name'], ['properties'=>['slug'=>$owner['slug']]]);
                wpig_upsert_edge($owner['uid'], $file_uid, 'owns_file', ['label'=>'Owns File']);
            }
            if ($ext === 'php' && strpos($relative, 'wp-content/uploads/') === 0) {
                $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, 'php_upload', 'critical', 98, 'PHP file found inside uploads directory', 'PHP In Uploads', null, null, 'PHP files in uploads are commonly suspicious and should be manually reviewed.', 'builtin');
            }

            if (preg_match('/\.(phtml|phar|php\.(jpg|jpeg|png|gif)|ico)$/i', $relative)) {
                $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, 'suspicious_executable_extension', 'high', 86, 'Suspicious executable-like file extension found', 'Executable File Extension Review', null, basename($relative), 'Review suspicious executable extensions such as .phtml, .phar, .php.jpg, or payloads disguised as images/icons.', 'builtin');
            }

            if (strpos($relative, 'wp-content/mu-plugins/') === 0) {
                $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, 'mu_plugin_file_review', 'medium', 62, 'MU-plugin file found', 'MU-plugin Persistence Review', null, basename($relative), 'Must-use plugins load automatically and can be used for persistence. Review unfamiliar MU-plugin files.', 'builtin');
            }
            if ($file->getSize() > 900000) continue;
            $lines = @file($path);
            if (!is_array($lines)) continue;
            foreach ($lines as $line_num => $line) {
                foreach ($patterns as $needle=>$meta) {
                    if (stripos($line, $needle) !== false) {
                        if (wpig_is_signature_reference_line($relative, $line)) continue;
                        $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, sanitize_title($needle), $meta[0], $meta[1], 'Suspicious function pattern found in file', $meta[2], $line_num + 1, trim($line), 'This is an indicator only. Some legitimate plugins use advanced functions, but this should be reviewed.', 'builtin');
                    }
                }
            }
        }
    }
    return $summary;
}

function wpig_yara_scan($scan_paths = [], $rules_path = '') {
    $summary = ['scanner'=>'yara','files'=>0,'findings'=>0,'paths'=>array_keys($scan_paths), 'available'=>wpig_command_exists('yara')];
    if (!$summary['available']) { $summary['message'] = 'YARA command not available on server.'; return $summary; }
    $rules_path = $rules_path ? $rules_path : WPIG_PATH . 'rules/wpig-default.yar';
    if (!file_exists($rules_path)) { $summary['message'] = 'No YARA rules file found.'; return $summary; }
    foreach ($scan_paths as $root) {
        $cmd = 'yara -r ' . escapeshellarg($rules_path) . ' ' . escapeshellarg($root) . ' 2>&1';
        $output = @shell_exec($cmd);
        foreach (explode("\n", (string)$output) as $line) {
            $line = trim($line);
            if (!$line || stripos($line, 'error') !== false) continue;
            $parts = preg_split('/\s+/', $line, 2);
            if (count($parts) < 2) continue;
            $rule = $parts[0]; $path = $parts[1];
            if (!file_exists($path)) continue;
            $relative = str_replace(ABSPATH, '', $path);
            $owner = wpig_file_owner($relative);
            $file_uid = 'file:' . md5($relative);
            wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>['path'=>$relative,'scanner'=>'yara','owner_type'=>$owner['type'],'owner_name'=>$owner['name']]]);
            $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, $rule, 'critical', 96, 'YARA rule matched file', 'YARA Match', null, $rule, 'A YARA malware/signature rule matched this file. Review immediately.', 'yara');
        }
    }
    return $summary;
}

function wpig_clamav_scan($scan_paths = []) {
    $summary = ['scanner'=>'clamav','files'=>0,'findings'=>0,'paths'=>array_keys($scan_paths), 'available'=>wpig_command_exists('clamscan')];
    if (!$summary['available']) { $summary['message'] = 'clamscan command not available on server.'; return $summary; }
    foreach ($scan_paths as $root) {
        $cmd = 'clamscan -r --infected --no-summary ' . escapeshellarg($root) . ' 2>&1';
        $output = @shell_exec($cmd);
        foreach (explode("\n", (string)$output) as $line) {
            $line = trim($line);
            if (!$line || strpos($line, ':') === false || stripos($line, 'FOUND') === false) continue;
            [$path, $rest] = explode(':', $line, 2);
            $signature = trim(str_replace('FOUND', '', $rest));
            if (!file_exists($path)) continue;
            $relative = str_replace(ABSPATH, '', $path);
            $owner = wpig_file_owner($relative);
            $file_uid = 'file:' . md5($relative);
            wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>['path'=>$relative,'scanner'=>'clamav','owner_type'=>$owner['type'],'owner_name'=>$owner['name']]]);
            $summary = wpig_record_file_finding($summary, $file_uid, $relative, $owner, $signature, 'critical', 99, 'ClamAV malware signature matched file', 'ClamAV Match', null, $signature, 'ClamAV reported this file as infected. Review immediately.', 'clamav');
        }
    }
    return $summary;
}

function wpig_maldet_scan($scan_paths = []) {
    $summary = ['scanner'=>'maldet','files'=>0,'findings'=>0,'paths'=>array_keys($scan_paths), 'available'=>wpig_command_exists('maldet')];
    if (!$summary['available']) { $summary['message'] = 'maldet command not available on server.'; return $summary; }
    foreach ($scan_paths as $root) {
        $cmd = 'maldet -a ' . escapeshellarg($root) . ' 2>&1';
        $output = @shell_exec($cmd);
        $summary['message'] = trim(substr((string)$output, 0, 1000));
        $scan_uid = 'scanner:maldet:' . md5($root . time());
        wpig_upsert_node($scan_uid, 'malware_scanner', 'Maldet Scan Result', ['properties'=>['path'=>$root,'output'=>$summary['message']]]);
    }
    return $summary;
}


/* ---------------- WordPress Code Quality / Security Helpers ---------------- */

function wpig_line_number_from_offset($contents, $offset) {
    return substr_count(substr($contents, 0, max(0, (int)$offset)), "\n") + 1;
}

function wpig_quality_add_file_finding_from_match(&$summary, $file_uid, $relative, $owner, $key, $severity, $score, $title, $indicator, $contents, $match, $description) {
    $offset = isset($match[0][1]) ? (int) $match[0][1] : 0;
    $snippet = isset($match[0][0]) ? trim(substr($match[0][0], 0, 260)) : '';
    $line = wpig_line_number_from_offset($contents, $offset);
    $summary = wpig_record_file_finding(
        $summary,
        $file_uid,
        $relative,
        $owner,
        $key,
        $severity,
        $score,
        $title,
        $indicator,
        $line,
        $snippet,
        $description,
        'code_quality'
    );
}

function wpig_quality_check_php_file($contents, $relative, $file_uid, $owner, &$summary) {
    $checks = [
        'unprepared_sql_query' => [
            '/\\$wpdb->(?:query|get_results|get_row|get_col|get_var)\\s*\\(\\s*(?!\\$wpdb->prepare)(?:"[^"]*\\$|\\\'[^\\\']*\\$|[^;]*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\.\\s*\\$))/is',
            'high',
            84,
            'Potential unprepared SQL query',
            'SQL Preparation Review',
            'Dynamic SQL should use $wpdb->prepare() with placeholders before calling query/get_results/get_row/get_var.'
        ],
        'superglobal_inside_sql' => [
            '/\\$wpdb->(?:query|get_results|get_row|get_col|get_var)\\s*\\([^;]*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE)/is',
            'critical',
            92,
            'Request input appears inside SQL query',
            'SQL Injection Risk',
            'Request data inside SQL should be sanitized, validated, and passed through $wpdb->prepare().'
        ],
        'dangerous_sql_operation' => [
            '/\\b(DROP\\s+TABLE|TRUNCATE\\s+TABLE|ALTER\\s+TABLE|DELETE\\s+FROM|UPDATE\\s+wp_options)\\b/i',
            'high',
            78,
            'Dangerous SQL operation found',
            'Destructive SQL Review',
            'Destructive SQL operations should be reviewed carefully and protected by capability checks, nonces, and backups.'
        ],
        'hardcoded_wp_table' => [
            '/\\bwp_(posts|postmeta|options|users|usermeta|terms|term_taxonomy|term_relationships|comments|commentmeta)\\b/i',
            'medium',
            52,
            'Hardcoded WordPress table name found',
            'Database Prefix Review',
            'Avoid hardcoded wp_ table names. Prefer $wpdb properties or $wpdb->prefix for compatibility with custom prefixes.'
        ],
        'register_rest_route_no_permission' => [
            '/register_rest_route\\s*\\((?:(?!permission_callback).){0,1200}\\)/is',
            'high',
            82,
            'REST route may be missing permission_callback',
            'REST Permission Review',
            'REST routes should define permission_callback. Public routes should be intentional and safe.'
        ],
        'rest_permission_return_true' => [
            '/permission_callback\\s*[\\\'"]?\\s*=>\\s*[\\\'"]__return_true[\\\'"]/i',
            'medium',
            66,
            'REST route uses public permission callback',
            'Public REST Route Review',
            'permission_callback => __return_true makes the route public. Confirm this is intentional, especially for write actions.'
        ],
        'ajax_nopriv_action' => [
            '/add_action\\s*\\(\\s*[\\\'"]wp_ajax_nopriv_/i',
            'high',
            80,
            'Unauthenticated AJAX action registered',
            'AJAX Exposure Review',
            'wp_ajax_nopriv actions are accessible to unauthenticated visitors. Review nonce, validation, rate limits, and write operations.'
        ],
        'admin_post_handler' => [
            '/add_action\\s*\\(\\s*[\\\'"]admin_post(?:_nopriv)?_/i',
            'medium',
            58,
            'Admin post handler registered',
            'Admin POST Handler Review',
            'Admin post handlers should check nonce, capability, sanitization, and redirect/exit behavior.'
        ],
        'missing_nonce_hint' => [
            '/(\\$_POST|\\$_REQUEST|add_action\\s*\\(\\s*[\\\'"]wp_ajax_|add_action\\s*\\(\\s*[\\\'"]admin_post_)/i',
            'medium',
            56,
            'Input/action handler needs nonce review',
            'Nonce Review',
            'Review this handler for check_admin_referer(), check_ajax_referer(), wp_verify_nonce(), and appropriate capability checks.'
        ],
        'missing_capability_hint' => [
            '/(update_option|delete_option|wp_insert_post|wp_update_post|wp_delete_post|wp_create_user|wp_update_user|media_handle_upload|wp_handle_upload|file_put_contents|unlink)\\s*\\(/i',
            'high',
            76,
            'Sensitive operation needs capability review',
            'Capability Review',
            'Sensitive write/delete/upload operations should be protected with current_user_can() and nonce checks.'
        ],
        'direct_superglobal_access' => [
            '/(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE)\\s*\\[[^\\]]+\\]/i',
            'medium',
            55,
            'Direct request input access found',
            'Sanitization Review',
            'Request input should be sanitized and validated before use. Use sanitize_text_field(), absint(), esc_url_raw(), wp_kses_post(), etc.'
        ],
        'potential_unescaped_echo' => [
            '/\\becho\\s+(?!esc_html\\s*\\(|esc_attr\\s*\\(|esc_url\\s*\\(|esc_textarea\\s*\\(|wp_kses_post\\s*\\(|wp_json_encode\\s*\\()\\$[a-zA-Z_][a-zA-Z0-9_]*(?:\\[[^\\]]+\\])?/i',
            'high',
            74,
            'Potential unescaped output',
            'Output Escaping Review',
            'Variables echoed into HTML should usually be escaped with esc_html(), esc_attr(), esc_url(), esc_textarea(), or wp_kses_post().'
        ],
        'unsafe_dynamic_include' => [
            '/\\b(include|include_once|require|require_once)\\s*\\([^;]*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\.\\s*\\$|\\$[a-zA-Z_][a-zA-Z0-9_]*)/i',
            'critical',
            90,
            'Dynamic include/require pattern found',
            'File Inclusion Review',
            'Dynamic include/require can lead to local/remote file inclusion if not strictly controlled.'
        ],
        'unsafe_file_write' => [
            '/\\b(file_put_contents|fwrite|fopen|unlink|move_uploaded_file|ZipArchive|copy|rename)\\s*\\([^;]*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\$[a-zA-Z_][a-zA-Z0-9_]*)/i',
            'high',
            82,
            'Dynamic file operation found',
            'File Operation Review',
            'File write/delete/upload operations should validate paths, extensions, nonces, and capabilities.'
        ],
        'remote_request_no_timeout' => [
            '/\\b(wp_remote_get|wp_remote_post|wp_safe_remote_get|wp_safe_remote_post)\\s*\\((?:(?!timeout).){0,500}\\)/is',
            'low',
            38,
            'Remote request may be missing timeout/error handling',
            'HTTP Request Review',
            'Remote requests should include timeout, is_wp_error() handling, and response validation.'
        ],
        'non_wp_http_request' => [
            '/(file_get_contents\\s*\\(\\s*[\\\'"]https?:\\/\\/|curl_exec\\s*\\()/i',
            'medium',
            54,
            'Non-WordPress HTTP request found',
            'HTTP API Review',
            'Prefer wp_remote_get()/wp_remote_post() so requests use WordPress HTTP API behavior and filters.'
        ],
        'hardcoded_secret_expanded' => [
            '/(api[_-]?key|secret|token|password|bearer|authorization|private[_-]?key|client[_-]?secret|stripe[_-]?secret|sendgrid|resend|openai|aws[_-]?access[_-]?key|aws[_-]?secret)\\s*[\\]=:]\\s*[\\\'"][A-Za-z0-9_\\-\\.\\$\\/\\+]{16,}/i',
            'critical',
            94,
            'Possible hardcoded secret found',
            'Secret Management Review',
            'Secrets should not be committed in plugin/theme code. Move them to environment variables or protected settings.'
        ],
        'debug_output' => [
            '/\\b(var_dump|print_r|debug_backtrace|error_reporting|ini_set\\s*\\(\\s*[\\\'"]display_errors|console\\.log|echo\\s+\\$wpdb->last_error)\\b/i',
            'low',
            34,
            'Debug output or error display pattern found',
            'Debug Leakage Review',
            'Debug output can expose sensitive information in production. Remove or gate behind WP_DEBUG and capabilities.'
        ],
        'rewrite_flush_runtime' => [
            '/flush_rewrite_rules\\s*\\(/i',
            'high',
            78,
            'flush_rewrite_rules() found',
            'Rewrite Flush Review',
            'flush_rewrite_rules() should usually run only on activation/deactivation, not on every request.'
        ],
        'unbounded_query' => [
            '/(posts_per_page\\s*[\\\'"]?\\s*=>\\s*-1|numberposts\\s*[\\\'"]?\\s*=>\\s*-1)/i',
            'medium',
            56,
            'Unbounded WordPress query found',
            'Performance Query Review',
            'Unbounded queries can cause memory/performance problems. Add limits or pagination where possible.'
        ],
        'wp_query_missing_no_found_rows' => [
            '/new\\s+WP_Query\\s*\\((?:(?!no_found_rows).){0,800}\\)/is',
            'low',
            35,
            'WP_Query may be missing no_found_rows',
            'Query Performance Review',
            'If pagination is not needed, add no_found_rows => true for better performance.'
        ],
        'autoload_update_option' => [
            '/update_option\\s*\\([^;]{0,500}\\)/is',
            'low',
            32,
            'update_option() usage found',
            'Options Autoload Review',
            'Review whether this option should autoload and avoid update_option() on every request.'
        ],
        'cron_schedule_no_guard' => [
            '/wp_schedule_event\\s*\\((?:(?!wp_next_scheduled).){0,600}\\)/is',
            'medium',
            62,
            'wp_schedule_event may be missing wp_next_scheduled guard',
            'Cron Lifecycle Review',
            'Before scheduling recurring events, check wp_next_scheduled() to avoid duplicate cron jobs.'
        ],
        'save_post_guard_review' => [
            '/add_action\\s*\\(\\s*[\\\'"]save_post[\\\'"]/i',
            'medium',
            50,
            'save_post hook registered',
            'save_post Guard Review',
            'save_post callbacks should guard against autosaves, revisions, permissions, and nonce failures.'
        ],
        'exposed_sensitive_file_reference' => [
            '/\\.(sql|bak|old|zip|tar|gz|env|log)([\\\'"\\s\\)]|$)/i',
            'medium',
            60,
            'Reference to sensitive file extension found',
            'Exposed File Review',
            'Backups, archives, .env, and logs should not be publicly accessible inside web directories.'
        ],
    ];

    foreach ($checks as $key => $check) {
        if (preg_match($check[0], $contents, $m, PREG_OFFSET_CAPTURE)) {
            wpig_quality_add_file_finding_from_match($summary, $file_uid, $relative, $owner, $key, $check[1], $check[2], $check[3], $check[4], $contents, $m, $check[5]);
        }
    }
}

function wpig_scan_sensitive_public_files($paths, &$summary) {
    foreach ($paths as $root) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $count = 0;
        foreach ($it as $file) {
            if ($count >= 2400) break;
            if (!$file->isFile()) continue;
            $count++;
            $path = $file->getPathname();
            $relative = str_replace(ABSPATH, '', $path);
            if (wpig_should_skip_self_scan_file($relative)) continue;
            $basename = strtolower(basename($relative));
            $ext = strtolower(pathinfo($relative, PATHINFO_EXTENSION));
            $sensitive = in_array($ext, ['sql','bak','old','zip','tar','gz','log'], true) || in_array($basename, ['.env','composer.lock','package-lock.json','yarn.lock'], true) || strpos($relative, 'node_modules/') !== false;
            if (!$sensitive) continue;

            $owner = wpig_file_owner($relative);
            $file_uid = 'file:' . md5($relative);
            wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>[
                'path'=>$relative,
                'extension'=>$ext,
                'size'=>@filesize($path),
                'owner_type'=>$owner['type'],
                'owner_name'=>$owner['name'],
            ]]);
            if (!empty($owner['uid'])) {
                wpig_upsert_node($owner['uid'], $owner['type'], $owner['name'], ['properties'=>['slug'=>$owner['slug']]]);
                wpig_upsert_edge($owner['uid'], $file_uid, 'owns_file', ['label'=>'Owns File']);
            }

            $severity = in_array($ext, ['sql','bak','log'], true) || $basename === '.env' ? 'high' : 'medium';
            $score = $severity === 'high' ? 82 : 58;
            $summary = wpig_record_file_finding(
                $summary,
                $file_uid,
                $relative,
                $owner,
                'public_sensitive_file',
                $severity,
                $score,
                'Potentially sensitive file found in web-accessible directory',
                'Supply Chain / Exposed File Review',
                null,
                $relative,
                'Review whether this backup/archive/config/dependency file should be publicly accessible. Move sensitive files outside the web root.',
                'code_quality'
            );
        }
    }
}


/* ---------------- Code Quality Scanner ---------------- */

function wpig_code_quality_paths_from_request($paths = []) {
    $allowed = [
        'plugins' => WP_CONTENT_DIR . '/plugins',
        'themes' => WP_CONTENT_DIR . '/themes',
        'mu_plugins' => WP_CONTENT_DIR . '/mu-plugins',
    ];
    if (empty($paths) || !is_array($paths)) $paths = ['plugins','themes'];
    $resolved = [];
    foreach ($paths as $key) {
        $key = sanitize_key($key);
        if (isset($allowed[$key]) && is_dir($allowed[$key]) && is_readable($allowed[$key])) {
            $resolved[$key] = $allowed[$key];
        }
    }
    return $resolved;
}

function wpig_normalize_function_body($body) {
    $tokens = @token_get_all("<?php\n" . $body);
    if (!is_array($tokens)) return md5(preg_replace('/\s+/', '', $body));
    $out = [];
    foreach ($tokens as $tok) {
        if (is_array($tok)) {
            $id = $tok[0]; $text = $tok[1];
            if (in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG], true)) continue;
            if ($id === T_VARIABLE) { $out[] = '$v'; continue; }
            if ($id === T_STRING) { $out[] = strtolower($text); continue; }
            if ($id === T_LNUMBER || $id === T_DNUMBER) { $out[] = '0'; continue; }
            if ($id === T_CONSTANT_ENCAPSED_STRING) { $out[] = '"s"'; continue; }
            $out[] = trim($text);
        } else {
            if (trim($tok) !== '') $out[] = $tok;
        }
    }
    return md5(implode('', $out));
}

function wpig_extract_php_symbols($path, $relative) {
    $code = @file_get_contents($path);
    if ($code === false) return [];
    $tokens = @token_get_all($code);
    if (!is_array($tokens)) return [];

    $symbols = [];
    $class_stack = [];
    $pending_class = null;
    $brace_depth = 0;
    $count = count($tokens);

    $previous_significant = function($index) use ($tokens) {
        for ($k = $index - 1; $k >= 0; $k--) {
            $t = $tokens[$k];
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) continue;
            return $t;
        }
        return null;
    };

    for ($i = 0; $i < $count; $i++) {
        $tok = $tokens[$i];
        $text = is_array($tok) ? $tok[1] : $tok;

        if ($text === '{') {
            $brace_depth++;
            if ($pending_class) {
                $pending_class['depth'] = $brace_depth;
                $class_stack[] = $pending_class;
                $pending_class = null;
            }
            continue;
        }

        if ($text === '}') {
            while (!empty($class_stack) && end($class_stack)['depth'] >= $brace_depth) {
                array_pop($class_stack);
            }
            $brace_depth = max(0, $brace_depth - 1);
            continue;
        }

        if (!is_array($tok)) {
            continue;
        }

        if ($tok[0] === T_CLASS || $tok[0] === T_INTERFACE || $tok[0] === T_TRAIT) {
            // Ignore anonymous classes: new class {}
            $prev = $previous_significant($i);
            if (is_array($prev) && $prev[0] === T_NEW) {
                continue;
            }

            $type = $tok[0] === T_INTERFACE ? 'interface' : ($tok[0] === T_TRAIT ? 'trait' : 'class');
            for ($j = $i + 1; $j < $count; $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $name = $tokens[$j][1];
                    $pending_class = ['name'=>$name, 'type'=>$type, 'line'=>(int)$tok[2], 'depth'=>null];
                    $symbols[] = [
                        'kind'=>$type, 'name'=>$name, 'class'=>'', 'line'=>(int)$tok[2], 'end_line'=>(int)$tok[2],
                        'body_hash'=>'', 'body_lines'=>0, 'file'=>$relative
                    ];
                    break;
                }
                if ($tokens[$j] === '{' || $tokens[$j] === ';') break;
            }
        }

        if ($tok[0] === T_FUNCTION) {
            $name = null;
            for ($j = $i + 1; $j < $count; $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $name = $tokens[$j][1];
                    break;
                }
                if ($tokens[$j] === '(') break; // closure
            }
            if (!$name) continue;

            $brace_start = null;
            $fn_brace_depth = 0;
            $body = '';
            $end_line = (int)$tok[2];

            for ($j = $i; $j < $count; $j++) {
                $tt = $tokens[$j];
                $tt_text = is_array($tt) ? $tt[1] : $tt;

                if ($tt_text === '{') {
                    if ($brace_start === null) $brace_start = $j;
                    $fn_brace_depth++;
                } elseif ($tt_text === '}') {
                    $fn_brace_depth--;
                    if ($brace_start !== null && $fn_brace_depth === 0) {
                        $end_line = is_array($tt) ? (int)$tt[2] : $end_line;
                        break;
                    }
                }

                if ($brace_start !== null) $body .= $tt_text;
                if (is_array($tt)) $end_line = (int)$tt[2];
            }

            $active_class = !empty($class_stack) ? end($class_stack) : null;
            $kind = $active_class ? 'method' : 'function';
            $class = $active_class ? $active_class['name'] : '';
            $body_lines = max(1, $end_line - (int)$tok[2] + 1);

            $symbols[] = [
                'kind'=>$kind,
                'name'=>$name,
                'class'=>$class,
                'line'=>(int)$tok[2],
                'end_line'=>$end_line,
                'body_hash'=>wpig_normalize_function_body($body),
                'body_lines'=>$body_lines,
                'file'=>$relative,
            ];
        }
    }

    return $symbols;
}


function wpig_run_code_quality_scan($paths = [], $options = []) {
    wpig_cleanup_self_plugin_findings();
    $scan_id = wpig_start_scan_row('code_quality');
    $paths = wpig_code_quality_paths_from_request($paths);
    $summary = ['scanner'=>'code_quality','paths'=>array_keys($paths),'files'=>0,'symbols'=>0,'findings'=>0,'duplicate_names'=>0,'duplicate_bodies'=>0,'large_functions'=>0];

    $symbols = [];
    foreach ($paths as $root) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $count = 0;
        foreach ($it as $file) {
            if ($count >= 1600) break;
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            $relative = str_replace(ABSPATH, '', $path);
            if (wpig_should_skip_self_scan_file($relative)) continue;
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if ($ext !== 'php') continue;
            $count++; $summary['files']++;
            $owner = wpig_file_owner($relative);
            $file_uid = 'file:' . md5($relative);
            wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>[
                'path'=>$relative,'directory'=>dirname($relative),'extension'=>$ext,'modified'=>gmdate('c',$file->getMTime()),
                'size'=>$file->getSize(),'sha1'=>@sha1_file($path),'owner_type'=>$owner['type'],'owner_name'=>$owner['name'],
            ]]);
            if (!empty($owner['uid'])) {
                wpig_upsert_node($owner['uid'], $owner['type'], $owner['name'], ['properties'=>['slug'=>$owner['slug']]]);
                wpig_upsert_edge($owner['uid'], $file_uid, 'owns_file', ['label'=>'Owns File']);
            }
            $contents_for_quality = @file_get_contents($path);
            if (is_string($contents_for_quality)) {
                wpig_quality_check_php_file($contents_for_quality, $relative, $file_uid, $owner, $summary);
                $quality_checks = [

                    'supply_chain_update_override' => ['/(pre_set_site_transient_update_plugins|pre_set_site_transient_update_themes|plugins_api|site_transient_update_plugins|update_plugins|auto_update_plugin|auto_update_theme)/i', 'high', 78, 'Plugin/theme update flow override found', 'Supply-chain Update Review', 'Review update-source overrides, auto-update filters, and plugin/theme update manipulation.'],
                    'mu_plugin_persistence_pattern' => ['/(WPMU_PLUGIN_DIR|mu-plugins|must-use|wp-content\/mu-plugins)/i', 'medium', 64, 'MU-plugin persistence-related code found', 'MU-plugin Persistence Review', 'Review unfamiliar MU-loader logic.'],
                    'db_persistent_payload_pattern' => ['/(set_transient|set_site_transient|update_option|add_option)\s*\([^;]*(base64|eval|gzinflate|str_rot13|openssl_decrypt|payload|backdoor|redirect)/is', 'high', 84, 'Potential DB-persistent payload pattern found', 'Database Persistence Review', 'Review options/transients storing encoded payloads, redirects, or executable-looking content.'],
                    'ai_prompt_injection_pattern' => ['/(ignore previous instructions|system prompt|jailbreak|prompt injection|RAG poisoning|OpenAI|Anthropic|HuggingFace|api\.openai\.com|api\.anthropic\.com)/i', 'medium', 58, 'AI prompt/API-risk pattern found', 'AI-era Payload Review', 'Review hidden prompt instructions, AI API tokens/endpoints, webhook abuse, or RAG/agent poisoning payloads.'],
                    'telegram_discord_c2_pattern' => ['/(api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|pastebin\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com|tor2web|\.onion)/i', 'high', 82, 'Suspicious callback/payload domain found', 'C2 / Payload Fetch Review', 'Review outbound callbacks to Telegram, Discord webhooks, Pastebin, GitHub raw URLs, or Tor/onion gateways.'],
                    'webshell_family_string' => ['/(WSO|FilesMan|IndoXploit|r57shell|c99shell|Mini Shell|b374k|file manager|shell_exec|cmd=|pass=)/i', 'critical', 94, 'Known webshell/fake file-manager string found', 'Webshell Fingerprint Review', 'Review for webshell family strings, fake file managers, command parameters, or browser terminal behavior.'],

                    'todo_comment' => ['/\b(TODO|FIXME|HACK)\b/i', 'low', 25, 'TODO/FIXME/HACK comment found', 'Code Cleanup', 'Developer reminder comments should be reviewed and either resolved or turned into tracked tasks.'],
                    'direct_superglobal' => ['/(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\s*\[/i', 'medium', 55, 'Direct superglobal access found', 'Input Sanitization Review', 'Review this code path and ensure all user input is sanitized, validated, and nonce/capability checked where needed.'],
                    'raw_sql_interpolation' => ['/\$wpdb->query\s*\([^;]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[^\)]*)/is', 'high', 72, 'Potential raw SQL query pattern found', 'SQL Preparation Review', 'Review this query and prefer $wpdb->prepare() for dynamic values.'],
                    'error_suppression' => ['/@(file_get_contents|include|require|unlink|fopen|curl_exec)\s*\(/i', 'low', 35, 'Error suppression operator found', 'Error Handling Review', 'The @ operator can hide failures. Consider explicit error handling/logging.'],
                    'hardcoded_secret' => ['/(api[_-]?key|secret|token|password)\s*[\]=:]\s*[\'\"][A-Za-z0-9_\-\.]{16,}/i', 'high', 82, 'Possible hardcoded secret found', 'Secret Management Review', 'Secrets should not be committed in theme/plugin code. Move secrets to environment variables or protected options.'],
                    'missing_nonce_hint' => ['/(add_action\s*\(\s*[\'\"]wp_ajax_|admin_post_|\$_POST|\$_REQUEST)/i', 'medium', 56, 'Input/action handler needs nonce and capability review', 'Nonce/Capability Review', 'Review this handler for check_admin_referer(), wp_verify_nonce(), current_user_can(), sanitization, and escaping.'],
                    'remote_request_no_timeout' => ['/(wp_remote_get|wp_remote_post)\s*\([^;]{0,220}\);/is', 'low', 38, 'Remote request should be reviewed for timeout/error handling', 'HTTP Request Review', 'Remote requests should include timeout, error handling, and response validation where appropriate.'],
                    'possible_dead_shortcode' => ['/add_shortcode\s*\(/i', 'low', 28, 'Shortcode registration found', 'Usage Review', 'Confirm this shortcode is still used in content and documentation.'], 
                ];
                foreach ($quality_checks as $check_key => $check) {
                    if (preg_match($check[0], $contents_for_quality, $m, PREG_OFFSET_CAPTURE)) {
                        $before = substr($contents_for_quality, 0, $m[0][1]);
                        $line_number = substr_count($before, "\n") + 1;
                        $summary = wpig_record_file_finding(
                            $summary, $file_uid, $relative, $owner, $check_key, $check[1], $check[2],
                            $check[3], $check[4], $line_number, trim(substr($m[0][0], 0, 220)), $check[5], 'code_quality'
                        );
                    }
                }
            }

            $file_symbols = wpig_extract_php_symbols($path, $relative);
            foreach ($file_symbols as $s) {
                $s['owner'] = $owner;
                $s['file_uid'] = $file_uid;
                $symbols[] = $s;

                $node_type = $s['kind'] === 'method' ? 'method' : ($s['kind'] === 'function' ? 'function' : $s['kind']);
                $symbol_uid = 'code:' . $s['kind'] . ':' . md5($s['file'] . ':' . $s['class'] . ':' . $s['name'] . ':' . $s['line']);
                $label = $s['kind'] === 'method' ? $s['class'] . '::' . $s['name'] . '()' : $s['name'] . ($s['kind'] === 'function' ? '()' : '');
                wpig_upsert_node($symbol_uid, $node_type, $label, ['properties'=>$s]);
                wpig_upsert_edge($file_uid, $symbol_uid, 'defines', ['label'=>'Defines']);
                $summary['symbols']++;

                if (in_array($s['kind'], ['function','method'], true) && (int)$s['body_lines'] >= (int) wpig_get_settings()['large_function_lines']) {
                    $summary = wpig_record_file_finding(
                        $summary, $file_uid, $relative, $owner, 'large_' . $s['kind'], 'medium', 58,
                        'Large ' . $s['kind'] . ' found',
                        'Large Function Refactor',
                        $s['line'],
                        $label . ' spans ' . $s['body_lines'] . ' lines',
                        'Large functions/methods are harder to maintain and may be candidates for extraction into smaller helpers.',
                        'code_quality'
                    );
                    $summary['large_functions']++;
                }

                if (in_array($s['kind'], ['function','method'], true) && preg_match('/\b(wpdb|\$wpdb)\b/i', (string)($s['name'] . ' ' . $s['file'])) === 0) {
                    // Reserved lightweight hook for future SQL-specific checks.
                }
            }
        }
    }

    $by_name = [];
    $by_hash = [];
    foreach ($symbols as $s) {
        if (!in_array($s['kind'], ['function','method','class','trait','interface'], true)) continue;
        $name_key = $s['kind'] . ':' . strtolower($s['class'] ? $s['class'] . '::' . $s['name'] : $s['name']);
        $by_name[$name_key][] = $s;
        if (in_array($s['kind'], ['function','method'], true) && !empty($s['body_hash']) && (int)$s['body_lines'] >= 8) {
            $by_hash[$s['body_hash']][] = $s;
        }
    }

    foreach ($by_name as $key => $group) {
        if (count($group) < 2) continue;
        $summary['duplicate_names']++;
        $group_uid = 'duplicate:name:' . md5($key);
        wpig_upsert_node($group_uid, 'duplicate_group', 'Duplicate name: ' . $key, ['properties'=>['count'=>count($group),'group_key'=>$key,'type'=>'duplicate_name']]);
        foreach ($group as $s) {
            $file_uid = $s['file_uid'];
            $owner = $s['owner'];
            $summary = wpig_record_file_finding(
                $summary, $file_uid, $s['file'], $owner, 'duplicate_name_' . md5($key), 'medium', 62,
                'Duplicate ' . $s['kind'] . ' name found',
                'Duplicate Code Refactor',
                $s['line'],
                ($s['class'] ? $s['class'] . '::' : '') . $s['name'],
                'This symbol name appears in multiple files/locations. Review for accidental duplication or refactor into a shared helper.',
                'code_quality'
            );
            $finding_uid = 'finding:code_quality:' . md5($s['file'] . ':duplicate_name_' . md5($key) . ':' . $s['line'] . ':' . (($s['class'] ? $s['class'] . '::' : '') . $s['name']));
            wpig_upsert_edge($group_uid, $finding_uid, 'has_duplicate_instance', ['label'=>'Duplicate Instance']);
        }
    }

    foreach ($by_hash as $hash => $group) {
        if (count($group) < 2) continue;
        $summary['duplicate_bodies']++;
        $group_uid = 'duplicate:body:' . $hash;
        wpig_upsert_node($group_uid, 'duplicate_group', 'Duplicate function body', ['properties'=>['count'=>count($group),'body_hash'=>$hash,'type'=>'duplicate_body']]);
        foreach ($group as $s) {
            $file_uid = $s['file_uid'];
            $owner = $s['owner'];
            $summary = wpig_record_file_finding(
                $summary, $file_uid, $s['file'], $owner, 'duplicate_body_' . $hash, 'medium', 68,
                'Repeated function/method body found',
                'Repeated Code Refactor',
                $s['line'],
                ($s['class'] ? $s['class'] . '::' : '') . $s['name'] . '() body hash: ' . substr($hash, 0, 10),
                'This function/method body appears to be repeated. Consider extracting shared logic into a helper, trait, service class, or reusable method.',
                'code_quality'
            );
            $finding_uid = 'finding:code_quality:' . md5($s['file'] . ':duplicate_body_' . $hash . ':' . $s['line'] . ':' . (($s['class'] ? $s['class'] . '::' : '') . $s['name'] . '() body hash: ' . substr($hash, 0, 10)));
            wpig_upsert_edge($group_uid, $finding_uid, 'has_duplicate_body_instance', ['label'=>'Duplicate Body']);
        }
    }


    wpig_scan_sensitive_public_files($paths, $summary);
    wpig_scan_plugin_update_findings($summary);
    wpig_scan_theme_update_findings($summary);

    // Lightweight unused-code heuristic: if a function/method name appears only once in scanned code, flag it for review.
    // This is intentionally conservative-low severity because dynamic WordPress callbacks can be hard to trace.
    $all_code_text = '';
    foreach ($paths as $root) {
        $it2 = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $c2 = 0;
        foreach ($it2 as $file2) {
            if ($c2 >= 1600) break;
            if (!$file2->isFile()) continue;
            if (strtolower(pathinfo($file2->getPathname(), PATHINFO_EXTENSION)) !== 'php') continue;
            $c2++;
            $chunk = @file_get_contents($file2->getPathname(), false, null, 0, 500000);
            if (is_string($chunk)) $all_code_text .= "\n" . $chunk;
        }
    }
    foreach ($symbols as $s) {
        if (!in_array($s['kind'], ['function','method'], true)) continue;
        if (strlen($s['name']) < 5 || strpos($s['name'], '__') === 0) continue;
        $occurrences = preg_match_all('/\b' . preg_quote($s['name'], '/') . '\b/', $all_code_text);
        if ($occurrences <= 1) {
            $summary = wpig_record_file_finding(
                $summary, $s['file_uid'], $s['file'], $s['owner'], 'possibly_unused_' . $s['kind'], 'low', 32,
                'Possibly unused ' . $s['kind'] . ' found',
                'Unused Code Review',
                $s['line'],
                ($s['class'] ? $s['class'] . '::' : '') . $s['name'] . '() only appears at its definition in scanned files',
                'This is a heuristic. WordPress hooks, callbacks, templates, and dynamic calls can create false positives. Review before removing.',
                'code_quality'
            );
        }
    }

    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}


/* ---------------- Plugin / Theme Update Intelligence ---------------- */

function wpig_scan_plugin_update_findings(&$summary) {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    if (!function_exists('wp_update_plugins')) {
        require_once ABSPATH . 'wp-includes/update.php';
    }

    wp_update_plugins();
    $plugins = get_plugins();
    $updates = get_site_transient('update_plugins');
    $response = isset($updates->response) && is_array($updates->response) ? $updates->response : [];

    foreach ($plugins as $plugin_file => $data) {
        if (strpos($plugin_file, wpig_self_plugin_slug() . '/') === 0) continue;
        $plugin_slug = dirname($plugin_file);
        if ($plugin_slug === '.') $plugin_slug = basename($plugin_file, '.php');
        $plugin_uid = 'plugin:' . $plugin_slug;
        wpig_upsert_node($plugin_uid, 'plugin', $data['Name'] ?: $plugin_slug, [
            'properties' => [
                'slug' => $plugin_slug,
                'version' => $data['Version'] ?? '',
                'plugin_file' => $plugin_file,
            ],
        ]);

        if (isset($response[$plugin_file])) {
            $new_version = $response[$plugin_file]->new_version ?? '';
            $fuid = 'finding:plugin_update:' . md5($plugin_file . ':' . $new_version);
            wpig_add_finding($fuid, 'code_quality_scan', 'medium', 64, 'Plugin update available', [
                'description' => 'Outdated plugins can create security, compatibility, and maintainability risk. Review changelog and update safely.',
                'source_type' => 'plugin',
                'source_uid' => $plugin_uid,
                'matched_pattern' => 'plugin_update_available',
                'matched_snippet' => ($data['Version'] ?? '') . ' → ' . $new_version,
                'owner_type' => 'plugin',
                'owner_name' => $data['Name'] ?? $plugin_slug,
                'evidence' => [
                    'plugin_file' => $plugin_file,
                    'current_version' => $data['Version'] ?? '',
                    'new_version' => $new_version,
                    'scanner' => 'code_quality',
                ],
            ]);
            wpig_upsert_node($fuid, 'finding', 'Plugin update available', ['properties'=>['severity'=>'medium','score'=>64,'finding_type'=>'code_quality_scan','scanner'=>'code_quality']]);
            wpig_upsert_node('indicator:plugin-update-available', 'plugin_update', 'Plugin Update Available', []);
            wpig_upsert_edge($plugin_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
            wpig_upsert_edge($fuid, 'indicator:plugin-update-available', 'classified_as', ['label'=>'Classified As']);
            $summary['findings']++;
            $summary['plugin_updates'] = (int)($summary['plugin_updates'] ?? 0) + 1;
        }
    }
}

function wpig_scan_theme_update_findings(&$summary) {
    wp_update_themes();
    $updates = get_site_transient('update_themes');
    $response = isset($updates->response) && is_array($updates->response) ? $updates->response : [];
    foreach (wp_get_themes() as $slug => $theme) {
        $theme_uid = 'theme:' . $slug;
        wpig_upsert_node($theme_uid, 'theme', $theme->get('Name') ?: $slug, ['properties'=>['slug'=>$slug,'version'=>$theme->get('Version')]]);
        if (isset($response[$slug])) {
            $new_version = $response[$slug]['new_version'] ?? '';
            $fuid = 'finding:theme_update:' . md5($slug . ':' . $new_version);
            wpig_add_finding($fuid, 'code_quality_scan', 'medium', 62, 'Theme update available', [
                'description' => 'Outdated themes can create security, compatibility, and maintainability risk. Review changelog and update safely.',
                'source_type' => 'theme',
                'source_uid' => $theme_uid,
                'matched_pattern' => 'theme_update_available',
                'matched_snippet' => $theme->get('Version') . ' → ' . $new_version,
                'owner_type' => 'theme',
                'owner_name' => $theme->get('Name') ?: $slug,
                'evidence' => ['theme'=>$slug,'current_version'=>$theme->get('Version'),'new_version'=>$new_version,'scanner'=>'code_quality'],
            ]);
            wpig_upsert_node($fuid, 'finding', 'Theme update available', ['properties'=>['severity'=>'medium','score'=>62,'finding_type'=>'code_quality_scan','scanner'=>'code_quality']]);
            wpig_upsert_node('indicator:theme-update-available', 'plugin_update', 'Theme Update Available', []);
            wpig_upsert_edge($theme_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
            wpig_upsert_edge($fuid, 'indicator:theme-update-available', 'classified_as', ['label'=>'Classified As']);
            $summary['findings']++;
            $summary['theme_updates'] = (int)($summary['theme_updates'] ?? 0) + 1;
        }
    }
}



/* ---------------- Root / Config / Core Scanner ---------------- */

function wpig_root_scan_patterns() {
    return [
        'wp_config_remote_include' => ['/\\b(include|require|include_once|require_once)\\s*\\([^;]*(https?:\\/\\/|\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE)/i', 'critical', 96, 'Remote or dynamic include in root/config file', 'Root File Inclusion Review'],
        'wp_config_runtime_execution' => ['/(eval\\s*\\(|assert\\s*\\(|create_function\\s*\\(|preg_replace\\s*\\([^\\n]+\\/e)/i', 'critical', 95, 'Runtime code execution pattern in root/config file', 'Root Execution Review'],
        'encoded_payload_root' => ['/(base64_decode\\s*\\(|gzinflate\\s*\\(|str_rot13\\s*\\(|hex2bin\\s*\\(|pack\\s*\\(|openssl_decrypt\\s*\\()/i', 'high', 86, 'Encoded/encrypted payload pattern in root/config file', 'Encoded Payload Review'],
        'shell_root' => ['/(shell_exec\\s*\\(|passthru\\s*\\(|system\\s*\\(|proc_open\\s*\\(|popen\\s*\\()/i', 'critical', 94, 'Shell execution pattern in root/config file', 'Shell Execution Review'],
        'external_callback_root' => ['/(api\\.telegram\\.org|discord(?:app)?\\.com\\/api\\/webhooks|pastebin\\.com|raw\\.githubusercontent\\.com|gist\\.githubusercontent\\.com|\\.onion|tor2web)/i', 'high', 84, 'Suspicious callback/payload host in root/config file', 'Callback/Payload Review'],
        'seo_cloak_root' => ['/(Googlebot|bingbot|HTTP_USER_AGENT|casino|viagra|pharma|loan|payday|document\\.location|window\\.location|wp_redirect)/i', 'medium', 68, 'SEO spam/cloaking pattern in root/config file', 'SEO Cloaking Review'],
        'db_credential_exposure' => ['/(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)\\s*[\'"]?\\s*,\\s*[\'"][^\'"]+[\'"]/i', 'low', 35, 'Database credential constant found', 'wp-config Credential Presence'],
        'wp_secret_keys_present' => ['/(AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)\\s*[\'"]?\\s*,\\s*[\'"][^\'"]{20,}/i', 'low', 30, 'WordPress auth salt/key constant found', 'wp-config Key Presence'],
        'debug_enabled_root' => ['/define\\s*\\(\\s*[\'"]WP_DEBUG[\'"]\\s*,\\s*true\\s*\\)/i', 'medium', 58, 'WP_DEBUG appears enabled', 'Production Debug Review'],
        'display_errors_enabled' => ['/(WP_DEBUG_DISPLAY[\'"]\\s*,\\s*true|ini_set\\s*\\(\\s*[\'"]display_errors[\'"]\\s*,\\s*[\'"]?1)/i', 'medium', 62, 'Display errors appears enabled', 'Error Disclosure Review'],
        'disallow_file_edit_missing_hint' => ['/wp-config\\.php/i', 'info', 10, 'Review DISALLOW_FILE_EDIT setting', 'Hardening Review'],
    ];
}

function wpig_htaccess_patterns() {
    return [
        'htaccess_external_redirect' => ['/RewriteRule\\s+.*https?:\\/\\//i', 'high', 82, 'External redirect rule in .htaccess', 'Redirect Review'],
        'htaccess_user_agent_cloak' => ['/(RewriteCond\\s+%\\{HTTP_USER_AGENT\\}|Googlebot|bingbot|Yandex|Baiduspider)/i', 'high', 78, 'User-agent/bot cloaking rule in .htaccess', 'Cloaking Review'],
        'htaccess_php_uploads' => ['/(SetHandler\\s+application\\/x-httpd-php|AddType\\s+application\\/x-httpd-php|AddHandler\\s+.*php)/i', 'critical', 92, 'PHP execution handler rule in .htaccess', 'PHP Execution Review'],
        'htaccess_base64' => ['/(base64|eval|shell|cmd|passthru|pharma|casino|viagra|payday)/i', 'medium', 62, 'Suspicious keyword in .htaccess', 'htaccess Malware Keyword Review'],
    ];
}

function wpig_root_candidate_files() {
    $files = [];
    $names = [
        'wp-config.php', 'wp-config-sample.php', '.htaccess', 'index.php', 'wp-load.php',
        'wp-settings.php', 'xmlrpc.php', 'wp-cron.php', 'wp-blog-header.php', 'php.ini',
        'user.ini', '.user.ini', '.env', 'error_log', 'debug.log'
    ];

    foreach ($names as $name) {
        $path = ABSPATH . $name;
        if (is_file($path) && is_readable($path)) {
            $files[] = $path;
        }
    }

    // Unknown root PHP and exposed archive/config files, shallow only.
    $root_files = @scandir(ABSPATH);
    if (is_array($root_files)) {
        foreach ($root_files as $name) {
            if ($name === '.' || $name === '..') continue;
            $path = ABSPATH . $name;
            if (!is_file($path) || !is_readable($path)) continue;
            $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            if (preg_match('/\\.(php|phtml|phar|sql|bak|old|zip|tar|gz|log|env)$/i', $name)) {
                $files[] = $path;
            }
        }
    }

    return array_values(array_unique($files));
}

function wpig_record_root_finding(&$summary, $relative, $key, $severity, $score, $title, $indicator, $line, $snippet, $description) {
    $file_uid = 'file:' . md5($relative);
    $owner = ['type'=>'root', 'name'=>'WordPress Root', 'slug'=>'root', 'uid'=>'root:wordpress'];
    wpig_upsert_node($owner['uid'], 'root', 'WordPress Root', ['properties'=>['path'=>ABSPATH]]);
    wpig_upsert_node($file_uid, 'root_file', basename($relative), ['properties'=>[
        'path'=>$relative,
        'scanner'=>'root_config',
        'extension'=>strtolower(pathinfo($relative, PATHINFO_EXTENSION)),
        'editor_url'=>wpig_graph_file_editor_url($relative),
    ]]);
    wpig_upsert_edge($owner['uid'], $file_uid, 'contains', ['label'=>'Contains']);

    $summary = wpig_record_file_finding(
        $summary,
        $file_uid,
        $relative,
        $owner,
        $key,
        $severity,
        $score,
        $title,
        $indicator,
        $line,
        $snippet,
        $description,
        'root_config'
    );

    return $summary;
}

function wpig_run_root_config_scan($include_core = false) {
    wpig_cleanup_self_plugin_findings();

    $scan_id = wpig_start_scan_row('root_config');
    $summary = [
        'scanner'=>'root_config',
        'files'=>0,
        'findings'=>0,
        'root_files'=>0,
        'core_files'=>0,
        'include_core'=>(bool)$include_core,
    ];

    $files = wpig_root_candidate_files();

    if ($include_core) {
        foreach ([ABSPATH . 'wp-admin', ABSPATH . 'wp-includes'] as $dir) {
            if (!is_dir($dir)) continue;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
            $count = 0;
            foreach ($it as $file) {
                if ($count >= 2500) break;
                if (!$file->isFile() || !$file->isReadable()) continue;
                $ext = strtolower(pathinfo($file->getPathname(), PATHINFO_EXTENSION));
                if (!in_array($ext, ['php','js','htaccess'], true)) continue;
                $files[] = $file->getPathname();
                $count++;
            }
        }
    }

    $files = array_values(array_unique($files));
    $summary['files'] = count($files);

    foreach ($files as $path) {
        $relative = str_replace(ABSPATH, '', $path);
        if (wpig_should_skip_self_scan_file($relative)) continue;

        $summary[strpos($relative, 'wp-admin/') === 0 || strpos($relative, 'wp-includes/') === 0 ? 'core_files' : 'root_files']++;

        $contents = @file_get_contents($path);
        if (!is_string($contents)) continue;

        $patterns = basename($relative) === '.htaccess' ? wpig_htaccess_patterns() : wpig_root_scan_patterns();

        foreach ($patterns as $key => $config) {
            [$regex, $severity, $score, $title, $indicator] = $config;
            if (!preg_match($regex, $contents, $m, PREG_OFFSET_CAPTURE)) continue;

            // DISALLOW_FILE_EDIT is a hardening hint only if missing in wp-config.
            if ($key === 'disallow_file_edit_missing_hint') {
                if (basename($relative) !== 'wp-config.php' || preg_match('/DISALLOW_FILE_EDIT\\s*[\'"]?\\s*,\\s*true/i', $contents)) {
                    continue;
                }
                $m = [['wp-config.php', 0]];
                $title = 'wp-config.php hardening review: DISALLOW_FILE_EDIT not found';
                $severity = 'low';
                $score = 28;
                $indicator = 'WordPress Hardening Review';
            }

            $offset = isset($m[0][1]) ? (int)$m[0][1] : 0;
            $line = substr_count(substr($contents, 0, $offset), "\n") + 1;
            $snippet = isset($m[0][0]) ? trim(substr($m[0][0], 0, 260)) : '';

            $desc = 'Root/config/core file security check. Review this finding manually before changing files.';
            if ($key === 'db_credential_exposure' || $key === 'wp_secret_keys_present') {
                $desc = 'This is expected inside wp-config.php but should never be exposed publicly or copied into plugins/themes/logs.';
            }

            $summary = wpig_record_root_finding($summary, $relative, $key, $severity, $score, $title, $indicator, $line, $snippet, $desc);
        }

        // Unknown root PHP file review.
        if (dirname($relative) === '.' && preg_match('/\\.php$/i', $relative)) {
            $known = ['index.php','wp-load.php','wp-settings.php','wp-config.php','wp-cron.php','wp-blog-header.php','xmlrpc.php','wp-activate.php','wp-comments-post.php','wp-links-opml.php','wp-login.php','wp-mail.php','wp-signup.php','wp-trackback.php'];
            if (!in_array(basename($relative), $known, true)) {
                $summary = wpig_record_root_finding(
                    $summary,
                    $relative,
                    'unknown_root_php_file',
                    'high',
                    80,
                    'Unknown PHP file found in WordPress root',
                    'Root Unknown PHP Review',
                    null,
                    basename($relative),
                    'Unexpected PHP files in the WordPress root can indicate webshells, droppers, or leftover install tools.'
                );
            }
        }

        // Exposed root backup/config files.
        if (preg_match('/\\.(sql|bak|old|zip|tar|gz|env|log)$/i', $relative)) {
            $summary = wpig_record_root_finding(
                $summary,
                $relative,
                'root_exposed_sensitive_file',
                preg_match('/\\.(sql|env|log)$/i', $relative) ? 'high' : 'medium',
                preg_match('/\\.(sql|env|log)$/i', $relative) ? 86 : 64,
                'Potentially exposed sensitive file in WordPress root',
                'Root Exposed File Review',
                null,
                basename($relative),
                'Backup, environment, archive, SQL, and log files should not be web-accessible from the WordPress root.'
            );
        }
    }

    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}

/* ---------------- Site + Malware scans ---------------- */

function wpig_run_site_graph_scan() {
    @set_time_limit(480);

    wpig_reset_graph();
    wpig_cleanup_self_plugin_findings();

    $scan_id = wpig_start_scan_row('site_graph');
    $summary = [
        'scanner' => 'site_graph',
        'posts' => 0,
        'terms' => 0,
        'links' => 0,
        'domains' => 0,
        'files' => 0,
        'findings' => 0,
        'ran' => [
            'site_graph' => true,
            'malware' => false,
            'code_quality' => false,
            'root_config' => false,
            'surface' => false,
            'media' => false,
        ],
        'results' => [],
    ];

    // 1. Build the regular site graph.
    $post_types = get_post_types(['public'=>true], 'names');
    $post_types = array_values(array_unique(array_merge($post_types, ['post','page'])));
    $q = new WP_Query([
        'post_type'=>$post_types,
        'post_status'=>['publish','draft','private','future','pending'],
        'posts_per_page'=>700,
        'fields'=>'ids',
        'no_found_rows'=>true,
        'orderby'=>'modified',
        'order'=>'DESC'
    ]);

    foreach ($q->posts as $post_id) {
        $p = get_post($post_id);
        if (!$p) continue;

        $uid = 'wp:post:' . $p->ID;
        wpig_upsert_node($uid, wpig_post_type_label($p->post_type), get_the_title($p), [
            'object_id'=>$p->ID,
            'object_type'=>$p->post_type,
            'url'=>get_permalink($p),
            'properties'=>[
                'status'=>$p->post_status,
                'modified'=>$p->post_modified_gmt,
                'word_count'=>str_word_count(wp_strip_all_tags($p->post_content))
            ]
        ]);
        $summary['posts']++;

        $author = get_userdata($p->post_author);
        if ($author) {
            $auid = 'wp:user:' . $author->ID;
            wpig_upsert_node($auid, 'user', $author->display_name, [
                'object_id'=>$author->ID,
                'object_type'=>'user',
                'properties'=>['roles'=>$author->roles]
            ]);
            wpig_upsert_edge($uid, $auid, 'written_by', ['label'=>'Written By']);
        }

        foreach (get_object_taxonomies($p->post_type) as $tax) {
            $terms = wp_get_object_terms($p->ID, $tax);
            if (is_wp_error($terms)) continue;
            foreach ($terms as $term) {
                $tuid = 'wp:term:' . $tax . ':' . $term->term_id;
                wpig_upsert_node($tuid, 'term', $term->name, [
                    'object_id'=>$term->term_id,
                    'object_type'=>$tax,
                    'url'=>get_term_link($term),
                    'properties'=>['taxonomy'=>$tax,'slug'=>$term->slug]
                ]);
                wpig_upsert_edge($uid, $tuid, 'has_term', ['label'=>'Has Term','properties'=>['taxonomy'=>$tax]]);
                $summary['terms']++;
            }
        }

        $thumb = get_post_thumbnail_id($p->ID);
        if ($thumb) {
            $muid = 'wp:media:' . $thumb;
            wpig_upsert_node($muid, 'media', get_the_title($thumb), [
                'object_id'=>$thumb,
                'object_type'=>'attachment',
                'url'=>wp_get_attachment_url($thumb)
            ]);
            wpig_upsert_edge($uid, $muid, 'has_featured_image', ['label'=>'Featured Image']);
        }

        preg_match_all('/href=[\'"]([^\'"]+)[\'"]/i', (string)$p->post_content, $m);
        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        foreach (array_unique($m[1] ?? []) as $href) {
            $href = html_entity_decode(trim($href));
            if (!$href || strpos($href,'#')===0 || strpos($href,'mailto:')===0 || strpos($href,'tel:')===0) continue;

            if (strpos($href,'//')===0) $url = 'https:' . $href;
            elseif (strpos($href,'/')===0) $url = home_url($href);
            elseif (preg_match('/^https?:\/\//i',$href)) $url = esc_url_raw($href);
            else continue;

            $host = wp_parse_url($url, PHP_URL_HOST);
            if ($host && $home_host && strtolower($host) === strtolower($home_host)) {
                $target = url_to_postid($url);
                if ($target) {
                    wpig_upsert_edge($uid, 'wp:post:' . $target, 'internal_links_to', ['label'=>'Internal Link','properties'=>['url'=>$url]]);
                } else {
                    $u = 'wp:url:' . md5($url);
                    wpig_upsert_node($u, 'internal_url', $url, ['url'=>$url]);
                    wpig_upsert_edge($uid, $u, 'links_to_internal_url', ['label'=>'Internal URL']);
                }
                $summary['links']++;
            } elseif ($host) {
                $duid = 'domain:' . strtolower($host);
                wpig_upsert_node($duid, 'external_domain', $host, ['url'=>'https://' . $host]);
                wpig_upsert_edge($uid, $duid, 'links_to_domain', ['label'=>'External Domain','properties'=>['url'=>$url]]);
                $summary['domains']++;
            }
        }
    }
    wp_reset_postdata();

    // 2. Run all non-media scans.
    $malware_paths = ['plugins','themes','uploads','mu_plugins'];
    $malware_engines = ['builtin'];
    if (class_exists('WPIG\\Scanner\\ScanManager')) {
        $malware_engines[] = 'advanced';
    }

    $malware = wpig_run_malware_scan($malware_engines, $malware_paths);
    $summary['ran']['malware'] = true;
    $summary['results']['malware'] = $malware;
    $summary['malware_summary'] = $malware;

    $quality = wpig_run_code_quality_scan(['plugins','themes','mu_plugins']);
    $summary['ran']['code_quality'] = true;
    $summary['results']['code_quality'] = $quality;
    $summary['code_quality_summary'] = $quality;

    $root_config = function_exists('wpig_run_root_config_scan')
        ? wpig_run_root_config_scan(false)
        : ['files'=>0,'findings'=>0,'message'=>'Root config scanner unavailable'];
    $summary['ran']['root_config'] = true;
    $summary['results']['root_config'] = $root_config;
    $summary['root_config_summary'] = $root_config;

    $surface = wpig_run_surface_scan(['cron','thirdparty_js','rest_api','open_ports']);
    $summary['ran']['surface'] = true;
    $summary['results']['surface'] = $surface;
    $summary['surface_summary'] = $surface;

    // 3. Combined totals. Media is intentionally excluded.
    $summary['malware_files'] = (int)($malware['files'] ?? 0);
    $summary['malware_findings'] = (int)($malware['findings'] ?? 0);

    $summary['code_quality_files'] = (int)($quality['files'] ?? 0);
    $summary['code_quality_symbols'] = (int)($quality['symbols'] ?? 0);
    $summary['code_quality_findings'] = (int)($quality['findings'] ?? 0);

    $summary['root_config_files'] = (int)($root_config['files'] ?? 0);
    $summary['root_config_findings'] = (int)($root_config['findings'] ?? 0);

    $summary['surface_findings'] = (int)($surface['findings'] ?? 0);
    $summary['surface_cron_events'] = (int)($surface['cron_events'] ?? 0);
    $summary['surface_rest_routes'] = (int)($surface['rest_routes'] ?? 0);
    $summary['surface_thirdparty_scripts'] = (int)($surface['thirdparty_scripts'] ?? 0);
    $summary['surface_open_ports'] = (int)($surface['open_ports'] ?? 0);

    $summary['files'] =
        $summary['malware_files'] +
        $summary['code_quality_files'] +
        $summary['root_config_files'];

    $summary['findings'] =
        $summary['malware_findings'] +
        $summary['code_quality_findings'] +
        $summary['root_config_findings'] +
        $summary['surface_findings'];

    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}


function wpig_run_advanced_malware_scan($scan_paths = []) {
    wpig_cleanup_self_plugin_findings();
    $summary = [
        'scanner' => 'advanced',
        'files' => 0,
        'findings' => 0,
        'paths' => array_keys($scan_paths),
        'parser_available' => class_exists('PhpParser\\ParserFactory'),
        'risk_scores' => [],
    ];

    if (!class_exists('WPIG\\Scanner\\ScanManager')) {
        $summary['message'] = 'Advanced scanner classes are not loaded.';
        return $summary;
    }

    $manager = new \WPIG\Scanner\ScanManager((int) (wpig_get_settings()['scan_file_limit'] ?? 2200));
    $result = $manager->run(array_values($scan_paths));
    $summary = array_merge($summary, [
        'files' => (int)($result['files'] ?? 0),
        'findings' => 0,
        'parser_available' => (bool)($result['parser_available'] ?? false),
        'risk_scores' => $result['risk_scores'] ?? [],
    ]);

    foreach (($result['results'] ?? []) as $finding) {
        $abs = $finding['file'] ?? '';
        if (!$abs) continue;
        $relative = str_replace(ABSPATH, '', $abs);
        if (wpig_should_skip_self_scan_file($relative)) continue;
        $owner = wpig_file_owner($relative);
        $file_uid = 'file:' . md5($relative);

        wpig_upsert_node($file_uid, 'file', basename($relative), ['properties'=>[
            'path'=>$relative,
            'directory'=>dirname($relative),
            'extension'=>strtolower(pathinfo($relative, PATHINFO_EXTENSION)),
            'scanner'=>'advanced',
            'owner_type'=>$owner['type'],
            'owner_name'=>$owner['name'],
            'sha1'=>@sha1_file($abs),
        ]]);

        if (!empty($owner['uid'])) {
            wpig_upsert_node($owner['uid'], $owner['type'], $owner['name'], ['properties'=>['slug'=>$owner['slug']]]);
            wpig_upsert_edge($owner['uid'], $file_uid, 'owns_file', ['label'=>'Owns File']);
        }

        $line = isset($finding['line']) ? absint($finding['line']) : null;
        $severity = sanitize_key($finding['severity'] ?? 'low');
        $type = sanitize_key($finding['type'] ?? 'advanced_finding');
        $engine = sanitize_key($finding['engine'] ?? 'advanced');
        $title = 'Advanced ' . strtoupper($engine) . ' finding: ' . str_replace('_', ' ', $type);
        $indicator = 'Advanced ' . strtoupper($engine) . ' Scanner';
        $snippet = $finding['snippet'] ?? ($finding['signature'] ?? '');
        $description = $finding['description'] ?? 'Advanced modular scanner finding.';

        $summary = wpig_record_file_finding(
            $summary,
            $file_uid,
            $relative,
            $owner,
            $type,
            $severity,
            $severity === 'critical' ? 95 : ($severity === 'high' ? 82 : ($severity === 'medium' ? 62 : 35)),
            $title,
            $indicator,
            $line,
            $snippet,
            $description,
            'advanced_' . $engine
        );
    }

    foreach (($result['risk_scores'] ?? []) as $risk) {
        $relative = str_replace(ABSPATH, '', $risk['file'] ?? '');
        if (!$relative) continue;
        $risk_uid = 'risk:' . md5($relative);
        $file_uid = 'file:' . md5($relative);
        wpig_upsert_node($risk_uid, 'malware_risk', ($risk['level'] ?? 'Risk') . ': ' . basename($relative), [
            'properties' => [
                'path' => $relative,
                'score' => (int)($risk['score'] ?? 0),
                'level' => $risk['level'] ?? '',
                'scanner' => 'advanced',
            ],
        ]);
        wpig_upsert_edge($file_uid, $risk_uid, 'has_risk_score', ['label'=>'Risk Score']);
    }

    return $summary;
}


function wpig_run_malware_scan($engines = [], $paths = []) {
    $scan_id = wpig_start_scan_row('malware');
    $paths = wpig_scan_paths_from_request($paths);
    if (empty($engines) || !is_array($engines)) $engines = ['builtin'];
    $summary = ['engines'=>$engines,'paths'=>array_keys($paths),'results'=>[],'findings'=>0,'files'=>0];

    foreach ($engines as $engine) {
        $engine = sanitize_key($engine);
        if ($engine === 'builtin') $result = wpig_builtin_malware_scan($paths);
        elseif ($engine === 'advanced') $result = wpig_run_advanced_malware_scan($paths);
        elseif ($engine === 'yara') $result = wpig_yara_scan($paths);
        elseif ($engine === 'clamav') $result = wpig_clamav_scan($paths);
        elseif ($engine === 'maldet') $result = wpig_maldet_scan($paths);
        else continue;
        $summary['results'][$engine] = $result;
        $summary['findings'] += (int)($result['findings'] ?? 0);
        $summary['files'] += (int)($result['files'] ?? 0);
    }
    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}


/* ---------------- Media Scanner ---------------- */

function wpig_run_media_scan($options = []) {
    $scan_id = wpig_start_scan_row('media');
    $settings = wpig_get_settings();
    $large_kb = isset($options['large_kb']) ? absint($options['large_kb']) : (int) $settings['large_media_kb'];
    if ($large_kb <= 0) $large_kb = 500;
    $large_bytes = $large_kb * 1024;
    $large_dim = (int) $settings['large_image_dimension'];

    $summary = [
        'scanner' => 'media',
        'attachments' => 0,
        'missing_alt' => 0,
        'missing_title' => 0,
        'missing_caption' => 0,
        'missing_description' => 0,
        'large_files' => 0,
        'large_dimensions' => 0,
        'findings' => 0,
        'large_kb_threshold' => $large_kb,
        'large_dimension_threshold' => $large_dim,
    ];

    $q = new WP_Query([
        'post_type' => 'attachment',
        'post_status' => 'inherit',
        'posts_per_page' => 1000,
        'fields' => 'ids',
        'no_found_rows' => true,
        'orderby' => 'modified',
        'order' => 'DESC',
    ]);

    foreach ($q->posts as $attachment_id) {
        $attachment = get_post($attachment_id);
        if (!$attachment) continue;
        $summary['attachments']++;

        $url = wp_get_attachment_url($attachment_id);
        $file_path = get_attached_file($attachment_id);
        $relative = $file_path ? str_replace(ABSPATH, '', $file_path) : '';
        $mime = get_post_mime_type($attachment_id);
        $alt = get_post_meta($attachment_id, '_wp_attachment_image_alt', true);
        $meta = wp_get_attachment_metadata($attachment_id);
        $size = ($file_path && file_exists($file_path)) ? filesize($file_path) : 0;

        $used_on = [];
        $usage_q = new WP_Query([
            'post_type' => get_post_types(['public'=>true], 'names'),
            'post_status' => ['publish','draft','private','pending','future'],
            'posts_per_page' => 25,
            'fields' => 'ids',
            'no_found_rows' => true,
            'meta_query' => [
                'relation' => 'OR',
                ['key' => '_thumbnail_id', 'value' => $attachment_id],
            ],
            's' => $url ? basename($url) : '',
        ]);
        foreach ($usage_q->posts as $used_post_id) {
            $up = get_post($used_post_id);
            if (!$up) continue;
            $used_on[] = [
                'id' => $used_post_id,
                'title' => get_the_title($used_post_id),
                'type' => $up->post_type,
                'url' => get_permalink($used_post_id),
                'edit_link' => get_edit_post_link($used_post_id, 'raw'),
                'usage' => (get_post_thumbnail_id($used_post_id) == $attachment_id) ? 'featured_image_or_content' : 'content_reference',
            ];
            wpig_upsert_node('wp:post:' . $used_post_id, wpig_post_type_label($up->post_type), get_the_title($used_post_id), [
                'object_id'=>$used_post_id,
                'object_type'=>$up->post_type,
                'url'=>get_permalink($used_post_id)
            ]);
            wpig_upsert_edge('wp:post:' . $used_post_id, 'wp:media:' . $attachment_id, 'uses_media', ['label'=>'Uses Media']);
        }
        wp_reset_postdata();

        $media_uid = 'wp:media:' . $attachment_id;
        wpig_upsert_node($media_uid, 'media', $attachment->post_title ?: basename((string)$relative), [
            'object_id' => $attachment_id,
            'object_type' => 'attachment',
            'url' => $url,
            'properties' => [
                'path' => $relative,
                'mime_type' => $mime,
                'size' => $size,
                'size_kb' => $size ? round($size / 1024, 1) : 0,
                'width' => isset($meta['width']) ? (int)$meta['width'] : null,
                'height' => isset($meta['height']) ? (int)$meta['height'] : null,
                'alt' => $alt,
                'edit_link' => get_edit_post_link($attachment_id, 'raw'),
                'thumb' => wp_get_attachment_image_url($attachment_id, 'medium'),
                'slug' => $attachment->post_name,
                'used_on' => $used_on,
                'title' => $attachment->post_title,
                'caption' => $attachment->post_excerpt,
                'description' => $attachment->post_content,
            ],
        ]);

        $checks = [
            'missing_alt' => [empty(trim((string)$alt)), 'Missing image alt text', 'Image Metadata Gap', 'medium', 55, 'Images should have descriptive alt text for accessibility and SEO.'],
            'missing_title' => [empty(trim((string)$attachment->post_title)), 'Missing image title', 'Image Metadata Gap', 'low', 35, 'Images should have a clear title for media library management.'],
            'missing_caption' => [empty(trim((string)$attachment->post_excerpt)), 'Missing image caption', 'Image Metadata Gap', 'low', 25, 'Captions are optional, but useful when images need visible context.'],
            'missing_description' => [empty(trim((string)$attachment->post_content)), 'Missing image description', 'Image Metadata Gap', 'low', 25, 'Descriptions help document media usage and context.'],
        ];

        foreach ($checks as $key => $check) {
            if ($check[0]) {
                $finding_uid = 'finding:media:' . md5($attachment_id . ':' . $key);
                wpig_add_finding($finding_uid, 'media_scan', $check[3], $check[4], $check[1], [
                    'description' => $check[5],
                    'source_type' => 'media',
                    'source_uid' => $media_uid,
                    'source_file' => $relative,
                    'matched_pattern' => $key,
                    'matched_snippet' => $url,
                    'evidence' => ['attachment_id'=>$attachment_id,'url'=>$url,'edit_link'=>get_edit_post_link($attachment_id, 'raw'),'path'=>$relative,'scanner'=>'media','used_on'=>$used_on,'fields'=>['alt'=>$alt,'title'=>$attachment->post_title,'caption'=>$attachment->post_excerpt,'description'=>$attachment->post_content,'slug'=>$attachment->post_name]],
                ]);
                wpig_upsert_node($finding_uid, 'finding', $check[1], ['properties'=>['severity'=>$check[3],'score'=>$check[4],'finding_type'=>'media_scan','scanner'=>'media']]);
                wpig_upsert_node('indicator:image-metadata-gap', 'media_issue', 'Image Metadata Gap', []);
                wpig_upsert_edge($media_uid, $finding_uid, 'has_finding', ['label'=>'Has Finding']);
                wpig_upsert_edge($finding_uid, 'indicator:image-metadata-gap', 'classified_as', ['label'=>'Classified As']);
                $summary[$key]++;
                $summary['findings']++;
            }
        }

        if ($size > $large_bytes) {
            $finding_uid = 'finding:media:' . md5($attachment_id . ':large_file');
            wpig_add_finding($finding_uid, 'media_scan', 'medium', 60, 'Large media file found', [
                'description' => 'Large media files can slow down pages. Consider compressing, resizing, converting to WebP/AVIF, or lazy-loading where appropriate.',
                'source_type' => 'media',
                'source_uid' => $media_uid,
                'source_file' => $relative,
                'matched_pattern' => 'large_file',
                'matched_snippet' => round($size / 1024, 1) . ' KB',
                'evidence' => ['attachment_id'=>$attachment_id,'size'=>$size,'size_kb'=>round($size/1024,1),'threshold_kb'=>$large_kb,'url'=>$url,'edit_link'=>get_edit_post_link($attachment_id, 'raw'),'path'=>$relative,'scanner'=>'media','used_on'=>$used_on,'fields'=>['alt'=>$alt,'title'=>$attachment->post_title,'caption'=>$attachment->post_excerpt,'description'=>$attachment->post_content,'slug'=>$attachment->post_name]],
            ]);
            wpig_upsert_node($finding_uid, 'finding', 'Large media file found', ['properties'=>['severity'=>'medium','score'=>60,'finding_type'=>'media_scan','scanner'=>'media']]);
            wpig_upsert_node('indicator:large-media-file', 'media_issue', 'Large Media File', []);
            wpig_upsert_edge($media_uid, $finding_uid, 'has_finding', ['label'=>'Has Finding']);
            wpig_upsert_edge($finding_uid, 'indicator:large-media-file', 'classified_as', ['label'=>'Classified As']);
            $summary['large_files']++;
            $summary['findings']++;
        }

        $w = isset($meta['width']) ? (int)$meta['width'] : 0;
        $h = isset($meta['height']) ? (int)$meta['height'] : 0;
        if ($large_dim > 0 && ($w > $large_dim || $h > $large_dim)) {
            $finding_uid = 'finding:media:' . md5($attachment_id . ':large_dimensions');
            wpig_add_finding($finding_uid, 'media_scan', 'low', 45, 'Large image dimensions found', [
                'description' => 'Images with very large dimensions may be oversized for web display. Consider generating/resizing responsive image sizes.',
                'source_type' => 'media',
                'source_uid' => $media_uid,
                'source_file' => $relative,
                'matched_pattern' => 'large_dimensions',
                'matched_snippet' => $w . 'x' . $h,
                'evidence' => ['attachment_id'=>$attachment_id,'width'=>$w,'height'=>$h,'threshold'=>$large_dim,'url'=>$url,'edit_link'=>get_edit_post_link($attachment_id, 'raw'),'path'=>$relative,'scanner'=>'media','used_on'=>$used_on,'fields'=>['alt'=>$alt,'title'=>$attachment->post_title,'caption'=>$attachment->post_excerpt,'description'=>$attachment->post_content,'slug'=>$attachment->post_name]],
            ]);
            wpig_upsert_node($finding_uid, 'finding', 'Large image dimensions found', ['properties'=>['severity'=>'low','score'=>45,'finding_type'=>'media_scan','scanner'=>'media']]);
            wpig_upsert_node('indicator:large-image-dimensions', 'media_issue', 'Large Image Dimensions', []);
            wpig_upsert_edge($media_uid, $finding_uid, 'has_finding', ['label'=>'Has Finding']);
            wpig_upsert_edge($finding_uid, 'indicator:large-image-dimensions', 'classified_as', ['label'=>'Classified As']);
            $summary['large_dimensions']++;
            $summary['findings']++;
        }
    }

    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}

/* ---------------- Exposure / Attack Surface Scanner ---------------- */

function wpig_is_external_url($url) {
    $host = wp_parse_url($url, PHP_URL_HOST);
    $home = wp_parse_url(home_url(), PHP_URL_HOST);
    return $host && $home && strtolower($host) !== strtolower($home);
}

function wpig_run_surface_scan($checks = []) {
    $scan_id = wpig_start_scan_row('surface');
    if (empty($checks) || !is_array($checks)) {
        $checks = ['cron','thirdparty_js','rest_api','open_ports'];
    }

    $summary = ['scanner'=>'surface','checks'=>$checks,'findings'=>0,'cron_events'=>0,'thirdparty_scripts'=>0,'rest_routes'=>0,'open_ports'=>0];

    if (in_array('cron', $checks, true)) {
        $cron = _get_cron_array();
        if (is_array($cron)) {
            foreach ($cron as $timestamp => $hooks) {
                foreach ($hooks as $hook => $events) {
                    $summary['cron_events']++;
                    $cron_uid = 'cron:' . md5($hook);
                    wpig_upsert_node($cron_uid, 'cron_job', $hook, ['properties'=>['next_run'=>$timestamp,'next_run_iso'=>gmdate('c',(int)$timestamp)]]);
                    $suspicious = preg_match('/(eval|base64|shell|exec|curl|remote|sync|import|backdoor|cache|tmp)/i', $hook);
                    if ($suspicious) {
                        $fuid = 'finding:surface:cron:' . md5($hook);
                        wpig_add_finding($fuid, 'surface_scan', 'medium', 58, 'Suspicious-looking cron hook name', [
                            'description'=>'Cron jobs can be used for persistence. Review unfamiliar hooks and confirm which plugin/theme registered them.',
                            'source_type'=>'cron','source_uid'=>$cron_uid,'matched_pattern'=>'cron_hook_name','matched_snippet'=>$hook,
                            'evidence'=>['hook'=>$hook,'next_run'=>$timestamp,'scanner'=>'surface'],
                        ]);
                        wpig_upsert_node($fuid, 'finding', 'Suspicious-looking cron hook name', ['properties'=>['severity'=>'medium','score'=>58,'finding_type'=>'surface_scan','scanner'=>'surface']]);
                        wpig_upsert_edge($cron_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
                        $summary['findings']++;
                    }
                }
            }
        }
    }

    if (in_array('thirdparty_js', $checks, true)) {
        $q = new WP_Query(['post_type'=>get_post_types(['public'=>true],'names'),'post_status'=>['publish','draft','private'],'posts_per_page'=>500,'fields'=>'ids','no_found_rows'=>true]);
        foreach ($q->posts as $post_id) {
            $p = get_post($post_id);
            if (!$p) continue;
            preg_match_all('/<script[^>]+src=[\'"]([^\'"]+)[\'"]/i', (string)$p->post_content, $m);
            foreach (array_unique($m[1] ?? []) as $src) {
                if (!wpig_is_external_url($src)) continue;
                $summary['thirdparty_scripts']++;
                $domain = wp_parse_url($src, PHP_URL_HOST);
                $script_uid = 'thirdparty-js:' . md5($src);
                $post_uid = 'wp:post:' . $post_id;
                wpig_upsert_node($post_uid, wpig_post_type_label($p->post_type), get_the_title($p), ['object_id'=>$post_id,'object_type'=>$p->post_type,'url'=>get_permalink($p)]);
                wpig_upsert_node($script_uid, 'thirdparty_script', $domain, ['url'=>$src,'properties'=>['src'=>$src,'domain'=>$domain]]);
                wpig_upsert_edge($post_uid, $script_uid, 'loads_thirdparty_script', ['label'=>'Loads Script']);
                $is_tracking = preg_match('/(googletagmanager|google-analytics|gtag|analytics|facebook|connect.facebook|fbq|hotjar|clarity|segment|mixpanel|matomo|pixel|doubleclick|adservice|adsystem)/i', $src);
                $title = $is_tracking ? 'Tracking script found in content' : 'Third-party JavaScript found in content';
                $score = $is_tracking ? 50 : 42;
                $fuid = 'finding:surface:thirdparty_js:' . md5($src . ':' . $post_id);
                wpig_add_finding($fuid, 'surface_scan', 'low', $score, $title, [
                    'description'=>'Third-party scripts should be reviewed for necessity, performance, privacy, and supply-chain risk.',
                    'source_type'=>'post','source_uid'=>$post_uid,'matched_pattern'=>$is_tracking ? 'tracking_script' : 'thirdparty_script','matched_snippet'=>$src,
                    'evidence'=>['src'=>$src,'domain'=>$domain,'post_id'=>$post_id,'scanner'=>'surface'],
                ]);
                wpig_upsert_node($fuid, 'finding', $title, ['properties'=>['severity'=>'low','score'=>$score,'finding_type'=>'surface_scan','scanner'=>'surface']]);
                wpig_upsert_edge($script_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
                $summary['findings']++;
            }
        }
        wp_reset_postdata();
    }

    if (in_array('rest_api', $checks, true)) {
        $server = rest_get_server();
        $routes = $server ? $server->get_routes() : [];
        foreach ($routes as $route => $handlers) {
            $summary['rest_routes']++;
            $route_uid = 'rest-route:' . md5($route);
            wpig_upsert_node($route_uid, 'api_endpoint', $route, ['properties'=>['route'=>$route]]);
            foreach ((array)$handlers as $handler) {
                if (!is_array($handler)) continue;
                $methods = isset($handler['methods']) ? array_keys(array_filter((array)$handler['methods'])) : [];
                $perm = $handler['permission_callback'] ?? null;
                $looks_public = empty($perm) || $perm === '__return_true';
                if ($looks_public && preg_match('/(users|settings|options|posts|media|wpig|admin|token|auth|upload|delete)/i', $route)) {
                    $fuid = 'finding:surface:rest:' . md5($route);
                    wpig_add_finding($fuid, 'surface_scan', 'medium', 65, 'Potentially exposed REST API endpoint', [
                        'description'=>'Review this REST route permission callback and confirm it is intentionally public.',
                        'source_type'=>'api_endpoint','source_uid'=>$route_uid,'matched_pattern'=>'public_rest_route','matched_snippet'=>$route,
                        'evidence'=>['route'=>$route,'methods'=>$methods,'scanner'=>'surface'],
                    ]);
                    wpig_upsert_node($fuid, 'finding', 'Potentially exposed REST API endpoint', ['properties'=>['severity'=>'medium','score'=>65,'finding_type'=>'surface_scan','scanner'=>'surface']]);
                    wpig_upsert_edge($route_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
                    $summary['findings']++;
                }
            }
        }
    }

    if (in_array('open_ports', $checks, true)) {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $ports = [21,22,25,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443];
        foreach ($ports as $port) {
            $errno = 0; $errstr = '';
            $conn = @fsockopen($host, $port, $errno, $errstr, 0.35);
            if ($conn) {
                fclose($conn);
                $summary['open_ports']++;
                $port_uid = 'open-port:' . $host . ':' . $port;
                wpig_upsert_node($port_uid, 'open_port', $host . ':' . $port, ['properties'=>['host'=>$host,'port'=>$port]]);
                if (!in_array($port, [80,443], true)) {
                    $fuid = 'finding:surface:open_port:' . md5($host . ':' . $port);
                    wpig_add_finding($fuid, 'surface_scan', in_array($port, [3306,5432,6379], true) ? 'high' : 'medium', in_array($port, [3306,5432,6379], true) ? 78 : 55, 'Open non-web port detected', [
                        'description'=>'Review whether this port should be reachable from the web server environment. Database/cache ports should not be publicly exposed.',
                        'source_type'=>'open_port','source_uid'=>$port_uid,'matched_pattern'=>'open_port','matched_snippet'=>$host . ':' . $port,
                        'evidence'=>['host'=>$host,'port'=>$port,'scanner'=>'surface'],
                    ]);
                    wpig_upsert_node($fuid, 'finding', 'Open non-web port detected', ['properties'=>['severity'=>in_array($port, [3306,5432,6379], true) ? 'high' : 'medium','score'=>in_array($port, [3306,5432,6379], true) ? 78 : 55,'finding_type'=>'surface_scan','scanner'=>'surface']]);
                    wpig_upsert_edge($port_uid, $fuid, 'has_finding', ['label'=>'Has Finding']);
                    $summary['findings']++;
                }
            }
        }
    }

    wpig_finish_scan_row($scan_id, $summary);
    return $summary;
}



/* ---------------- Scanner self-baseline / false-positive controls ---------------- */

function wpig_self_plugin_slug() {
    $base = plugin_basename(__FILE__);
    $dir = dirname($base);
    return $dir && $dir !== '.' ? $dir : 'wp-intelligence-graph';
}

function wpig_is_self_plugin_file($relative) {
    $relative = ltrim(wp_normalize_path((string) $relative), '/');
    $self = 'wp-content/plugins/' . trim(wpig_self_plugin_slug(), '/') . '/';
    return strpos($relative, $self) === 0;
}

function wpig_scan_self_plugin_enabled() {
    /**
     * Default false because scanner plugins contain malware signatures as strings.
     * Developers can enable with:
     * add_filter('wpig_scan_self_plugin', '__return_true');
     */
    return (bool) apply_filters('wpig_scan_self_plugin', false);
}

function wpig_should_skip_self_scan_file($relative) {
    return wpig_is_self_plugin_file($relative) && !wpig_scan_self_plugin_enabled();
}

function wpig_cleanup_self_plugin_findings() {
    global $wpdb;
    $t = wpig_tables();

    if (wpig_scan_self_plugin_enabled()) {
        return 0;
    }

    $like = $wpdb->esc_like('wp-content/plugins/' . wpig_self_plugin_slug() . '/') . '%';
    $rows = $wpdb->get_results(
        $wpdb->prepare("SELECT uid FROM {$t['findings']} WHERE source_file LIKE %s", $like),
        ARRAY_A
    );

    if (!$rows) {
        return 0;
    }

    $uids = array_values(array_filter(array_map(function($r) { return $r['uid'] ?? ''; }, $rows)));
    if (!$uids) {
        return 0;
    }

    $placeholders = implode(',', array_fill(0, count($uids), '%s'));

    $wpdb->query($wpdb->prepare("DELETE FROM {$t['edges']} WHERE source_uid IN ($placeholders) OR target_uid IN ($placeholders)", array_merge($uids, $uids)));
    $wpdb->query($wpdb->prepare("DELETE FROM {$t['nodes']} WHERE uid IN ($placeholders)", $uids));
    $wpdb->query($wpdb->prepare("DELETE FROM {$t['findings']} WHERE uid IN ($placeholders)", $uids));

    return count($uids);
}

function wpig_is_signature_reference_line($relative, $line) {
    $relative = wp_normalize_path((string) $relative);
    $line = (string) $line;

    if (!wpig_is_self_plugin_file($relative)) {
        return false;
    }

    $signature_context = preg_match('/(patterns\s*=|quality_checks\s*=|dangerous\s*=|weights\s*=|severityWeights|rule\s+WPIG_|RegexScanner|ASTScanner|RiskEngine|EntropyScanner|scanner\/|wpig-default\.yar)/i', $relative . ' ' . $line);
    $quoted_signature = preg_match('/[\'"](?:eval|base64_decode|gzinflate|shell_exec|passthru|system|exec|assert|str_rot13|create_function|chr|pack|unserialize|rawurldecode|urldecode|hex2bin|strrev|preg_replace|fsockopen|stream_socket_client|wp_create_user|wp_insert_user|add_role|add_cap|wp_mail)\s*\(?[\'"]?/i', $line);

    return (bool) ($signature_context || $quoted_signature);
}


/* ---------------- WordPress file editor helpers ---------------- */

function wpig_file_editor_url($relative, $owner = []) {
    $relative = ltrim((string) $relative, '/');
    if (!$relative) return '';

    // Theme files open in Appearance > Theme File Editor.
    if (strpos($relative, 'wp-content/themes/') === 0) {
        $parts = explode('/', $relative);
        $theme = $parts[2] ?? '';
        $file = implode('/', array_slice($parts, 3));
        if ($theme && $file) {
            return admin_url('theme-editor.php?theme=' . rawurlencode($theme) . '&file=' . rawurlencode($file));
        }
    }

    // Plugin files open in Plugins > Plugin File Editor.
    if (strpos($relative, 'wp-content/plugins/') === 0) {
        $file = preg_replace('#^wp-content/plugins/#', '', $relative);
        if ($file) {
            return admin_url('plugin-editor.php?file=' . rawurlencode($file));
        }
    }

    return '';
}


/* ---------------- Composer / dependency installer helpers ---------------- */

function wpig_dependency_status() {
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    $shell_exec_available = function_exists('shell_exec') && !in_array('shell_exec', $disabled, true);
    $composer_path = '';

    if ($shell_exec_available) {
        $composer_path = trim((string) @shell_exec('command -v composer 2>/dev/null'));
    }

    return [
        'vendor_autoload_exists' => file_exists(WPIG_PATH . 'vendor/autoload.php'),
        'php_parser_available' => class_exists('PhpParser\\ParserFactory'),
        'composer_json_exists' => file_exists(WPIG_PATH . 'composer.json'),
        'composer_lock_exists' => file_exists(WPIG_PATH . 'composer.lock'),
        'composer_available' => !empty($composer_path),
        'composer_path' => $composer_path,
        'shell_exec_available' => $shell_exec_available,
        'installer_enabled' => defined('WPIG_ALLOW_COMPOSER_INSTALL') && WPIG_ALLOW_COMPOSER_INSTALL,
        'plugin_path' => WPIG_PATH,
        'ssh_command' => 'cd ' . WPIG_PATH . ' && composer install --no-dev --optimize-autoloader',
    ];
}

function wpig_rest_dependency_status() {
    return rest_ensure_response(wpig_dependency_status());
}

function wpig_rest_install_composer() {
    if (!current_user_can('manage_options')) {
        return new WP_Error('wpig_forbidden', 'Not allowed.', ['status' => 403]);
    }

    if (!defined('WPIG_ALLOW_COMPOSER_INSTALL') || !WPIG_ALLOW_COMPOSER_INSTALL) {
        return new WP_Error(
            'wpig_composer_disabled',
            'Composer install is disabled. Add define("WPIG_ALLOW_COMPOSER_INSTALL", true); to wp-config.php to enable it.',
            ['status' => 403]
        );
    }

    $status = wpig_dependency_status();

    if (!$status['shell_exec_available']) {
        return new WP_Error('wpig_shell_disabled', 'shell_exec is disabled on this server.', ['status' => 400]);
    }

    if (!$status['composer_available'] || empty($status['composer_path'])) {
        return new WP_Error('wpig_composer_missing', 'Composer was not found on this server.', ['status' => 400]);
    }

    if (!$status['composer_json_exists']) {
        return new WP_Error('wpig_composer_json_missing', 'composer.json was not found in the plugin directory.', ['status' => 400]);
    }

    @set_time_limit(300);

    $cmd = 'cd ' . escapeshellarg(WPIG_PATH) . ' && ' . escapeshellarg($status['composer_path']) . ' install --no-dev --optimize-autoloader 2>&1';
    $output = @shell_exec($cmd);

    // Load autoloader immediately after install where possible.
    if (file_exists(WPIG_PATH . 'vendor/autoload.php')) {
        require_once WPIG_PATH . 'vendor/autoload.php';
    }

    $after = wpig_dependency_status();

    return rest_ensure_response([
        'success' => $after['php_parser_available'],
        'message' => $after['php_parser_available'] ? 'Composer dependencies installed and AST scanner is available.' : 'Composer command finished, but PHP Parser is still unavailable. Review output.',
        'output' => (string) $output,
        'status' => $after,
    ]);
}


/* ---------------- Graph path context helpers ---------------- */

function wpig_path_parent_nodes_for_file($relative) {
    $relative = ltrim((string) $relative, '/');
    if (!$relative) return [];

    $parts = explode('/', $relative);
    $nodes = [];
    $path = '';

    foreach ($parts as $index => $part) {
        if ($part === '') continue;
        $path = $path ? $path . '/' . $part : $part;
        $is_file = $index === count($parts) - 1;
        if ($is_file) break;

        $nodes[] = [
            'uid' => 'path:' . md5($path),
            'type' => 'folder',
            'label' => $part,
            'path' => $path,
            'parent_uid' => $index > 0 ? 'path:' . md5(implode('/', array_slice($parts, 0, $index))) : '',
        ];
    }

    return $nodes;
}

function wpig_graph_file_editor_url($relative) {
    if (function_exists('wpig_file_editor_url')) {
        return wpig_file_editor_url($relative, wpig_file_owner($relative));
    }

    $relative = ltrim((string) $relative, '/');

    if (strpos($relative, 'wp-content/themes/') === 0) {
        $parts = explode('/', $relative);
        $theme = $parts[2] ?? '';
        $file = implode('/', array_slice($parts, 3));
        if ($theme && $file) return admin_url('theme-editor.php?theme=' . rawurlencode($theme) . '&file=' . rawurlencode($file));
    }

    if (strpos($relative, 'wp-content/plugins/') === 0) {
        $file = preg_replace('#^wp-content/plugins/#', '', $relative);
        if ($file) return admin_url('plugin-editor.php?file=' . rawurlencode($file));
    }

    return '';
}

/* ---------------- Admin UI ---------------- */

add_action('admin_menu', function () {
    add_menu_page('WP Intelligence Graph', 'Intelligence Graph', 'manage_options', 'wp-intelligence-graph', 'wpig_admin_page', 'dashicons-networking', 58);
});

add_action('admin_enqueue_scripts', function ($hook) {
    if ($hook !== 'toplevel_page_wp-intelligence-graph') return;
    wp_enqueue_style('wpig-admin', WPIG_URL . 'admin/css/admin.css', [], WPIG_VERSION);
    wp_enqueue_script('wpig-cytoscape', 'https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js', [], '3.30.2', true);
    wp_enqueue_script('wpig-admin', WPIG_URL . 'admin/js/admin.js', ['wpig-cytoscape'], WPIG_VERSION, true);
    wp_localize_script('wpig-admin', 'WPIG_CONFIG', ['restUrl'=>esc_url_raw(rest_url('wpig/v1')), 'nonce'=>wp_create_nonce('wp_rest')]);
});

function wpig_admin_page() {
    if (!current_user_can('manage_options')) return; ?>
    <div class="wrap wpig-wrap">
        <div class="wpig-app-shell">
<div id="wpig-notice" class="wpig-notice" hidden></div>

            <div id="wpig-site-scan-progress" class="wpig-site-scan-progress" hidden>
                <div class="wpig-progress-card">
                    <div class="wpig-progress-header">
                        <div>
                            <span class="wpig-progress-eyebrow">Full Site Scan Running</span>
                            <h2>Scanning your WordPress environment</h2>
                            <p id="wpig-progress-message">Preparing scanner…</p>
                        </div>
                        <strong id="wpig-progress-percent">0%</strong>
                    </div>

                    <div class="wpig-progress-track" aria-hidden="true">
                        <span id="wpig-progress-bar"></span>
                    </div>

                    <div class="wpig-progress-steps">
                        <div class="wpig-progress-step is-active" data-progress-step="graph"><span>1</span><strong>Site Graph</strong><small>Posts, links, graph data</small></div>
                        <div class="wpig-progress-step" data-progress-step="malware"><span>2</span><strong>Malware</strong><small>Files, signatures, risk</small></div>
                        <div class="wpig-progress-step" data-progress-step="quality"><span>3</span><strong>Code Quality</strong><small>PHP checks, SQL, refactor</small></div>
                        <div class="wpig-progress-step" data-progress-step="root"><span>4</span><strong>Root / Config</strong><small>wp-config, .htaccess</small></div>
                        <div class="wpig-progress-step" data-progress-step="exposure"><span>5</span><strong>Exposure</strong><small>REST, cron, scripts, ports</small></div>
                        <div class="wpig-progress-step" data-progress-step="results"><span>6</span><strong>Results</strong><small>Rendering dashboards</small></div>
                    </div>

                    <div class="wpig-callout">
                        <strong>Media scan is excluded.</strong> Tabs and heavy graph sections are temporarily hidden while the full scan runs to keep the admin UI responsive.
                    </div>
                </div>
            </div>


            <nav class="wpig-tabs" aria-label="WP Intelligence Graph tabs">
                <button class="wpig-tab is-active" data-tab="overview">Overview</button>
                <button class="wpig-tab" data-tab="graph">Graph Explorer</button>
                <button class="wpig-tab" data-tab="findings">Findings <span id="wpig-findings-badge" class="wpig-tab-badge">0</span></button>
                <button class="wpig-tab" data-tab="malware">Malware Scanner</button>
                <button class="wpig-tab" data-tab="quality">Code Quality</button>
                <button class="wpig-tab" data-tab="media">Media Scanner</button>
                <button class="wpig-tab" data-tab="installer">Installer</button>
                <button class="wpig-tab" data-tab="settings">Settings</button>
            </nav>

            <section class="wpig-tab-panel is-active" data-panel="overview">
                <div class="wpig-overview-dashboard">
                    <div class="wpig-overview-header">
                        <div>
                            <span class="wpig-overview-eyebrow">Security Intelligence Overview</span>
                            <h2>WordPress Environment Health</h2>
                            <p>Review scanner coverage, finding severity, and priority issues before drilling into the graph.</p>
                        </div>
                        <div class="wpig-overview-actions">
                            <button id="wpig-overview-run-scan" class="button button-primary">Run Site Graph Scan</button>
                            <button id="wpig-overview-refresh" class="button">Refresh Overview</button>
                        </div>
                    </div>

                    <div class="wpig-overview-kpis">
                        <div class="wpig-card"><span>Total Findings</span><strong id="wpig-overview-total-findings">—</strong><small>Open review items</small></div>
                        <div class="wpig-card"><span>Critical / High</span><strong id="wpig-overview-priority-findings">—</strong><small>Needs attention first</small></div>
                        <div class="wpig-card"><span>Malware</span><strong id="wpig-overview-malware-findings">—</strong><small>Security indicators</small></div>
                        <div class="wpig-card"><span>Code Quality</span><strong id="wpig-overview-code-findings">—</strong><small>Refactor / PHP checks</small></div>
                        <div class="wpig-card"><span>Root / Config</span><strong id="wpig-overview-root-findings">—</strong><small>wp-config, .htaccess, root</small></div>
                        <div class="wpig-card"><span>Exposure</span><strong id="wpig-overview-exposure-findings">—</strong><small>REST, cron, scripts, ports</small></div>
                    </div>

                    <div class="wpig-overview-grid">
                        <div class="wpig-panel wpig-overview-panel">
                            <div class="wpig-panel-header">
                                <div>
                                    <h2>Findings by Scanner</h2>
                                    <p class="wpig-muted">Open findings grouped by scanner source.</p>
                                </div>
                            </div>
                            <div class="wpig-chart-layout">
                                <div id="wpig-overview-donut" class="wpig-donut" role="img" aria-label="Findings by scanner">
                                    <span>—</span>
                                </div>
                                <div id="wpig-overview-type-legend" class="wpig-chart-legend"></div>
                            </div>
                        </div>

                        <div class="wpig-panel wpig-overview-panel">
                            <div class="wpig-panel-header">
                                <div>
                                    <h2>Severity Breakdown</h2>
                                    <p class="wpig-muted">Critical and high items should be reviewed first.</p>
                                </div>
                            </div>
                            <div id="wpig-overview-severity-bars" class="wpig-severity-bars"></div>
                        </div>
                    </div>

                    <div class="wpig-overview-grid">
                        <div class="wpig-panel wpig-overview-panel">
                            <div class="wpig-panel-header">
                                <div>
                                    <h2>Priority Findings</h2>
                                    <p class="wpig-muted">Highest scoring critical/high findings across all scanners.</p>
                                </div>
                                <button class="button" id="wpig-overview-view-all-findings">View All Findings</button>
                            </div>
                            <div id="wpig-overview-priority-list" class="wpig-overview-finding-list">
                                <div class="wpig-empty-state"><strong>No priority findings loaded yet.</strong><span>Run a scan or refresh the overview.</span></div>
                            </div>
                        </div>

                        <div class="wpig-panel wpig-overview-panel">
                            <div class="wpig-panel-header">
                                <div>
                                    <h2>Scanner Coverage</h2>
                                    <p class="wpig-muted">Last full scan summary and graph coverage.</p>
                                </div>
                            </div>
                            <div id="wpig-overview-coverage" class="wpig-overview-coverage-grid"></div>
                        </div>
                    </div>

                    <div class="wpig-panel wpig-overview-panel">
                        <div class="wpig-panel-header">
                            <div>
                                <h2>Finding Queues</h2>
                                <p class="wpig-muted">Quickly jump into the right review queue.</p>
                            </div>
                        </div>
                        <div id="wpig-overview-queues" class="wpig-overview-queues"></div>
                    </div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="graph">
                <div class="wpig-panel">
                    <div class="wpig-panel-header wpig-graph-card-header">
                        <div>
                            <h2>Graph Explorer</h2>
                            <p id="wpig-graph-context">Showing the current site graph. Use filters or click a finding to isolate an issue.</p>
                        </div>
                        <div class="wpig-graph-header-actions">
                            <button type="button" id="wpig-toggle-graph-findings" class="button wpig-graph-findings-toggle" aria-expanded="false">
                                Findings <span id="wpig-graph-findings-count">0</span>
                            </button>
                            <div class="wpig-graph-theme-toggle" aria-label="Graph theme toggle">
                                <span>Graph Theme</span>
                                <button type="button" class="wpig-theme-option is-active" data-graph-theme="light">Light</button>
                                <button type="button" class="wpig-theme-option" data-graph-theme="dark">Dark</button>
                            </div>
                            <button type="button" id="wpig-reset-focus" class="button button-primary wpig-reset-graph-header">Reset Graph</button>
                        </div>
                    </div>
                    <div class="wpig-graph-card" id="wpig-graph-card">
                        <div id="wpig-graph"></div>
                        <div id="wpig-graph-loading" class="wpig-graph-loading" hidden>
                            <div class="wpig-graph-loading-card">
                                <span class="wpig-spinner"></span>
                                <strong>Loading Graph Explorer</strong>
                                <p id="wpig-graph-loading-message">Loading nodes, edges, and layout…</p>
                            </div>
                        </div>
                        <aside id="wpig-graph-findings-panel" class="wpig-graph-findings-panel" hidden>
                            <div class="wpig-graph-findings-head">
                                <div>
                                    <h3>Graph Findings</h3>
                                    <p>Click a finding to isolate the affected file/code nodes.</p>
                                </div>
                                
                            </div>
                            <div class="wpig-graph-findings-tools">
                                <button type="button" class="button button-small is-active" data-graph-finding-filter="all">All</button>
                                <button type="button" class="button button-small" data-graph-finding-filter="critical">Critical</button>
                                <button type="button" class="button button-small" data-graph-finding-filter="high">High</button>
                                <button type="button" class="button button-small" data-graph-finding-filter="code_quality">Code</button>
                                <button type="button" class="button button-small" data-graph-finding-filter="malware">Malware</button>
                                <button type="button" class="button button-small" data-graph-finding-filter="root_config">Root</button>
                            </div>
                            <div id="wpig-graph-findings-list" class="wpig-graph-findings-list">
                                <div class="wpig-graph-findings-empty">No findings loaded yet.</div>
                            </div>
                        </aside>
                    </div>
                    
                    <div class="wpig-graph-node-filter-card" id="wpig-graph-node-filter-card">
                        <div class="wpig-node-filter-header">
                            <div>
                                <h3>Node Filters</h3>
                                <p>Toggle the node types visible in the graph. Root/config nodes are hidden by default unless selected.</p>
                            </div>
                            <div class="wpig-node-filter-actions">
                                <button type="button" id="wpig-check-all-nodes" class="button button-small">Check All</button>
                                <button type="button" id="wpig-uncheck-all-nodes" class="button button-small">Uncheck All</button>
                            </div>
                        </div>
                        <fieldset>
                        <legend>Node filters</legend>
                        <?php
                        $filters = ['post'=>'Posts','page'=>'Pages','term'=>'Terms','user'=>'Users','media'=>'Media','media_issue'=>'Media Issues','thirdparty_script'=>'Third-party JS','api_endpoint'=>'API Endpoints','cron_job'=>'Cron Jobs','open_port'=>'Open Ports','supply_chain_issue'=>'Supply Chain Issues','wp_security_issue'=>'WP Security Issues','plugin_update'=>'Plugin Updates','seo_issue'=>'SEO Issues','legacy_php_issue'=>'Legacy PHP','folder'=>'Folders','root'=>'Root','root_file'=>'Root Files','file'=>'Files','function'=>'Functions','method'=>'Methods','class'=>'Classes','trait'=>'Traits','interface'=>'Interfaces','duplicate_group'=>'Duplicate Groups','refactor_opportunity'=>'Refactor Opportunities','finding'=>'Findings','malware_indicator'=>'Malware Indicators','root_config'=>'Root Config','malware_risk'=>'Malware Risk Scores','malware_scanner'=>'Scanner Results','surface_issue'=>'Surface Issues','external_domain'=>'External Domains','internal_url'=>'Internal URLs','plugin'=>'Plugins','theme'=>'Themes','option'=>'Options','uploads'=>'Uploads Area'];
                        foreach ($filters as $value=>$label) echo '<label><input type="checkbox" class="wpig-filter" value="'.esc_attr($value).'" checked> '.esc_html($label).'</label>';
                        ?>
                    </fieldset>
                    </div>

                    <div class="wpig-legend wpig-graph-color-key">
                        <span><i class="wpig-key-post"></i>Content</span>
                        <span><i class="wpig-key-file"></i>Files</span>
                        <span><i class="wpig-key-code"></i>Code Symbols</span>
                        <span><i class="wpig-key-quality"></i>Code Quality</span>
                        <span><i class="wpig-key-duplicate"></i>Duplicate / Refactor</span>
                        <span><i class="wpig-key-finding"></i>Findings</span>
                        <span><i class="wpig-key-malware"></i>Malware</span>
                        <span><i class="wpig-key-root"></i>Root / Config</span>
                        <span><i class="wpig-key-exposure"></i>Exposure</span>
                        <span><i class="wpig-key-plugin"></i>Plugin / Theme</span>
                        <span><i class="wpig-key-url"></i>URLs / Domains</span>
                        <span><i class="wpig-key-media"></i>Media</span>
                    </div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="findings">
                <div class="wpig-panel">
                    <div class="wpig-panel-header">
                        <div><h2>Findings</h2><p>Use scanner filters to focus the queue. Media findings include image previews, issue tabs, and inline edit controls.</p></div>
                        <button id="wpig-refresh-findings" class="button">Refresh Findings</button>
                    </div>
                    <div class="wpig-finding-filters">
                        <button class="button wpig-finding-filter is-active" data-finding-filter="all">All Open</button>
                        <button class="button wpig-finding-filter" data-finding-filter="malware">Malware</button>
                        <button class="button wpig-finding-filter" data-finding-filter="code_quality">Code Quality</button>
                        <button class="button wpig-finding-filter" data-finding-filter="media">Media</button>
                        <button class="button wpig-finding-filter" data-finding-filter="surface">Exposure</button>
                        <button class="button wpig-finding-filter" data-finding-filter="root_config">Root / Config</button>
                        <button class="button wpig-finding-filter" data-finding-filter="high">High/Critical</button>
                    </div>
                    <div id="wpig-findings-list" class="wpig-findings-list wide"><p>No findings loaded yet.</p></div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="malware">
<div class="wpig-sticky-actions">
                    <div>
                        <h2>Malware Scanner</h2>
                        <p>Run built-in and server scanner engines, then review malware and exposure KPIs before opening findings.</p>
                    </div>
                    <div class="wpig-action-row">
                        <button id="wpig-run-malware-scan" class="button button-primary button-hero">Run Malware Scan</button>
                            <button id="wpig-run-root-config-scan" class="button">Run Root / Config Scan</button>
                        <button id="wpig-run-surface-scan" class="button">Run Exposure Scan</button>
                        <button id="wpig-check-scanners" class="button">Check Availability</button>
                    </div>
                </div>

                <div class="wpig-quality-shell">
                    <div class="wpig-quality-tabs">
                        <button class="wpig-quality-tab is-active" data-malware-tab-main="results">Results</button>
                        <button class="wpig-quality-tab" data-malware-tab-main="setup">Scan Setup</button>
                        <button class="wpig-quality-tab" data-malware-tab-main="exposure">Exposure Checks</button>
                        <button class="wpig-quality-tab" data-malware-tab-main="availability">Availability</button>
                    </div>

                    <div class="wpig-quality-panel is-active" data-malware-panel-main="results">
                        <div class="wpig-panel">
                            <h2>Malware Scan Results</h2>
                            <p class="wpig-muted">This is the main malware view. Run a scanner to populate KPIs and review totals. Detailed files remain in Findings.</p>
                            <div id="wpig-malware-kpis" class="wpig-kpi-grid">
                                <div class="wpig-kpi"><span>Engines</span><strong>—</strong><small>Scanners used</small></div>
                                <div class="wpig-kpi"><span>Files</span><strong>—</strong><small>Files scanned</small></div>
                                <div class="wpig-kpi"><span>Findings</span><strong>—</strong><small>Review items</small></div>
                                <div class="wpig-kpi"><span>Paths</span><strong>—</strong><small>Directories checked</small></div>
                            </div>
                            <div id="wpig-malware-results" class="wpig-quality-dashboard">
                                <div class="wpig-empty-state">
                                    <strong>No malware scan has been run in this browser session yet.</strong>
                                    <span>Click Run Malware Scan above. Setup, exposure checks, and availability are in the tabs.</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-malware-panel-main="setup">
                        <div class="wpig-malware-layout">
                            <div class="wpig-panel">
                                <h2>Scanner Engines</h2>
                                <div class="wpig-form-section">
                                    <label><input type="checkbox" class="wpig-malware-engine" value="builtin" checked> Built-in Indicator Scanner</label>
                                    <label><input type="checkbox" class="wpig-malware-engine" value="advanced" checked> Advanced Modular Engine: Regex + AST + Entropy + Risk Score</label>
                                    <label><input type="checkbox" class="wpig-malware-engine" value="yara"> YARA, if installed</label>
                                    <label><input type="checkbox" class="wpig-malware-engine" value="clamav"> ClamAV, if installed</label>
                                    <label><input type="checkbox" class="wpig-malware-engine" value="maldet"> Maldet / Linux Malware Detect, if installed</label>
                                </div>
                            </div>
                            <div class="wpig-panel">
                                <h2>Scan Paths</h2>
                                <div class="wpig-form-section">
                                    <label><input type="checkbox" class="wpig-malware-path" value="plugins" checked> wp-content/plugins</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="themes" checked> wp-content/themes</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="uploads" checked> wp-content/uploads</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="root"> WordPress Root Files</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="core"> WordPress Core Files: wp-admin + wp-includes</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="mu_plugins"> wp-content/mu-plugins</label>
                                    <label><input type="checkbox" class="wpig-malware-path" value="wp_content"> all wp-content</label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-malware-panel-main="exposure">
                        <div class="wpig-panel">
                            <h2>Exposure Checks</h2>
                            <p class="wpig-muted">These are attack-surface checks inspired by scanner/recon workflows. Run them separately or alongside your review.</p>
                            <div class="wpig-checks-grid">
                                <label><input type="checkbox" class="wpig-surface-check" value="cron" checked> PHP / WordPress Cron Jobs</label>
                                <label><input type="checkbox" class="wpig-surface-check" value="thirdparty_js" checked> Third-party JavaScript in Content</label>
                                <label><input type="checkbox" class="wpig-surface-check" value="rest_api" checked> Exposed REST API Endpoints</label>
                                <label><input type="checkbox" class="wpig-surface-check" value="open_ports" checked> Basic Open Port Check on Site Host</label>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-malware-panel-main="availability">
                        <div class="wpig-panel">
                            <h2>Scanner Availability</h2>
                            <div id="wpig-malware-status" class="wpig-status-list"></div>
                            <div class="wpig-callout"><strong>Best practice:</strong> Keep built-in scanning enabled. Add YARA/ClamAV/Maldet on servers where command-line scanning is allowed.</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="quality">
                <div class="wpig-sticky-actions">
                    <div>
                        <h2>Code Quality Scanner</h2>
                        <p>Scan PHP files for duplicate code, SQL/security issues, maintainability gaps, and refactor opportunities.</p>
                    </div>
                    <div class="wpig-action-row">
                        <button id="wpig-run-quality-scan" class="button button-primary button-hero">Run Code Quality Scan</button>
                        <button id="wpig-quality-graph" class="button">View Quality Graph</button>
                    </div>
                </div>

                <div class="wpig-quality-shell">
                    <div class="wpig-quality-tabs">
                        <button class="wpig-quality-tab is-active" data-quality-tab="results">Results</button>
                        <button class="wpig-quality-tab" data-quality-tab="setup">Scan Setup</button>
                        <button class="wpig-quality-tab" data-quality-tab="checks">Checks Included</button>
                    </div>

                    <div class="wpig-quality-panel is-active" data-quality-panel="results">
                        <div class="wpig-panel">
                            <div class="wpig-panel-header">
                                <div>
                                    <h2>Code Quality Scan Results</h2>
                                    <p class="wpig-muted">This is the main view. Run a scan to populate the dashboard, then use the Findings tab for file-level review.</p>
                                </div>
                            </div>

                            <div id="wpig-quality-kpis" class="wpig-kpi-grid">
                                <div class="wpig-kpi"><span>Files</span><strong>—</strong><small>PHP files scanned</small></div>
                                <div class="wpig-kpi"><span>Symbols</span><strong>—</strong><small>Functions/classes/methods</small></div>
                                <div class="wpig-kpi"><span>Findings</span><strong>—</strong><small>Review items</small></div>
                                <div class="wpig-kpi"><span>Duplicates</span><strong>—</strong><small>Name/body groups</small></div>
                            </div>

                            <div id="wpig-quality-results" class="wpig-quality-dashboard">
                                <div class="wpig-empty-state">
                                    <strong>No code quality scan has been run in this browser session yet.</strong>
                                    <span>Click Run Code Quality Scan above. Setup and checks are available in the tabs.</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-quality-panel="setup">
                        <div class="wpig-panel">
                            <h2>Scan Setup</h2>
                            <p class="wpig-muted">Keep this focused on your custom code first. Start with themes and custom plugins before scanning everything.</p>
                            <div class="wpig-form-section">
                                <h3>Scan Paths</h3>
                                <label><input type="checkbox" class="wpig-quality-path" value="plugins" checked> wp-content/plugins</label>
                                <label><input type="checkbox" class="wpig-quality-path" value="themes" checked> wp-content/themes</label>
                                <label><input type="checkbox" class="wpig-quality-path" value="mu_plugins"> wp-content/mu-plugins</label>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-quality-panel="checks">
                        <div class="wpig-panel">
                            <h2>Checks Included</h2>
                            <p class="wpig-muted">These checks create review findings. They are indicators and should be manually validated before making code changes.</p>
                            <div class="wpig-checks-grid">
                                <label><input type="checkbox" checked disabled> Duplicate function/method/class names</label>
                                <label><input type="checkbox" checked disabled> Repeated normalized function/method bodies</label>
                                <label><input type="checkbox" checked disabled> Large functions/methods over 120 lines</label>
                                <label><input type="checkbox" checked disabled> TODO/FIXME/HACK comments</label>
                                <label><input type="checkbox" checked disabled> Direct superglobal access review</label>
                                <label><input type="checkbox" checked disabled> Potential raw SQL preparation review</label>
                                <label><input type="checkbox" checked disabled> Error suppression operator review</label>
                                <label><input type="checkbox" checked disabled> Refactor opportunity graph nodes</label>
                                <label><input type="checkbox" checked disabled> SQL preparation and request-input-in-SQL review</label>
                                <label><input type="checkbox" checked disabled> Nonce and capability checks for write actions</label>
                                <label><input type="checkbox" checked disabled> Escaping/sanitization review</label>
                                <label><input type="checkbox" checked disabled> REST/AJAX exposure checks</label>
                                <label><input type="checkbox" checked disabled> Unsafe file operations</label>
                                <label><input type="checkbox" checked disabled> Hardcoded secrets/API keys</label>
                                <label><input type="checkbox" checked disabled> Debug/error leakage</label>
                                <label><input type="checkbox" checked disabled> Performance smells and cron lifecycle</label>
                                <label><input type="checkbox" checked disabled> Exposed backup/archive/env/dependency files</label>
                                <label><input type="checkbox" checked disabled> Root / config file checks</label>
                                <label><input type="checkbox" checked disabled> .htaccess redirect/cloaking/PHP handler checks</label>
                                <label><input type="checkbox" checked disabled> Optional WordPress core file pattern scan</label>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="media">
                <div class="wpig-sticky-actions">
                    <div>
                        <h2>Media Scanner</h2>
                        <p>Review image metadata, oversized media, and where assets are used across the site.</p>
                    </div>
                    <div class="wpig-action-row">
                        <button id="wpig-run-media-scan" class="button button-primary button-hero">Run Media Scan</button>
                        <button id="wpig-media-graph" class="button">View Media Graph</button>
                    </div>
                </div>

                <div class="wpig-quality-shell">
                    <div class="wpig-quality-tabs">
                        <button class="wpig-quality-tab is-active" data-media-tab-main="results">Results</button>
                        <button class="wpig-quality-tab" data-media-tab-main="setup">Scan Setup</button>
                        <button class="wpig-quality-tab" data-media-tab-main="checks">Checks Included</button>
                    </div>

                    <div class="wpig-quality-panel is-active" data-media-panel-main="results">
                        <div class="wpig-panel">
                            <h2>Media Scan Results</h2>
                            <p class="wpig-muted">Run a scan to see KPI totals and a list of media issues with usage context.</p>
                            <div id="wpig-media-kpis" class="wpig-kpi-grid">
                                <div class="wpig-kpi"><span>Attachments</span><strong>—</strong><small>Media scanned</small></div>
                                <div class="wpig-kpi"><span>Findings</span><strong>—</strong><small>Review items</small></div>
                                <div class="wpig-kpi"><span>Missing Alt</span><strong>—</strong><small>Accessibility / SEO</small></div>
                                <div class="wpig-kpi"><span>Large Files</span><strong>—</strong><small>Performance review</small></div>
                            </div>
                            <div id="wpig-media-results" class="wpig-results-box wpig-media-results-list">
                                <div class="wpig-empty-state">
                                    <strong>No media scan has been run in this browser session yet.</strong>
                                    <span>Click Run Media Scan above. Setup and checks are available in the tabs.</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-media-panel-main="setup">
                        <div class="wpig-panel">
                            <h2>Scan Setup</h2>
                            <div class="wpig-form-section">
                                <h3>Thresholds</h3>
                                <label>Large file threshold KB <input id="wpig-media-large-kb" type="number" min="100" step="50" value="500"></label>
                            </div>
                        </div>
                    </div>

                    <div class="wpig-quality-panel" data-media-panel-main="checks">
                        <div class="wpig-panel">
                            <h2>Checks Included</h2>
                            <div class="wpig-checks-grid">
                                <label><input type="checkbox" checked disabled> Missing image alt text</label>
                                <label><input type="checkbox" checked disabled> Missing media title</label>
                                <label><input type="checkbox" checked disabled> Missing caption</label>
                                <label><input type="checkbox" checked disabled> Missing description</label>
                                <label><input type="checkbox" checked disabled> Large file size threshold</label>
                                <label><input type="checkbox" checked disabled> Large image dimensions threshold</label>
                                <label><input type="checkbox" checked disabled> Pages/posts using the image where detected</label>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="installer">
                <div class="wpig-panel wpig-dependency-panel">
                    <div class="wpig-panel-header">
                        <div>
                            <h2>Composer / AST Dependency Status</h2>
                            <p class="wpig-muted">The Advanced AST scanner uses <code>nikic/php-parser</code>. Install Composer dependencies to enable full AST scanning.</p>
                        </div>
                        <button id="wpig-dependency-refresh" class="button">Check Again</button>
                    </div>

                    <div id="wpig-dependency-status" class="wpig-dependency-status-grid"></div>

                    <div class="wpig-installer-actions">
                        <button id="wpig-run-composer-install" class="button button-primary">Run Composer Install</button>
                        <button id="wpig-copy-composer-command" class="button">Copy SSH Command</button>
                    </div>

                    <div class="wpig-callout">
                        <strong>Safety gate:</strong> The install button only works when <code>define('WPIG_ALLOW_COMPOSER_INSTALL', true);</code> is added to <code>wp-config.php</code>. This should be used on local/dev/staging or servers you control.
                    </div>

                    <div id="wpig-composer-output" class="wpig-composer-output" hidden></div>
                </div>

                <div class="wpig-grid-2">
                    <div class="wpig-panel">
                        <h2>Server Resource Installer</h2>
                        <p class="wpig-muted">WordPress plugins usually cannot safely install system packages on shared hosting. Use this tab to check what is available and copy the recommended server commands for your environment.</p>
                        <div id="wpig-installer-status" class="wpig-status-list"></div>
                        <div class="wpig-action-row">
                            <button id="wpig-installer-refresh" class="button button-primary">Refresh Availability</button>
                        </div>
                    </div>
                    <div class="wpig-panel">
                        <h2>Recommended Install Commands</h2>
                        <p class="wpig-muted">Run these via SSH as a server admin. After installing, return here and click Refresh Availability.</p>
                        <div id="wpig-install-commands" class="wpig-command-list"></div>
                    </div>
                </div>
                <div class="wpig-panel">
                    <h2>Best Default Settings</h2>
                    <ul class="wpig-feature-list">
                        <li><strong>Malware scan paths:</strong> plugins, themes, uploads. Add mu-plugins if your site uses them.</li>
                        <li><strong>Malware engines:</strong> built-in always on. Add YARA/ClamAV/Maldet only when installed on the server.</li>
                        <li><strong>Code quality paths:</strong> themes and custom plugins first. Avoid scanning all wp-content unless needed.</li>
                        <li><strong>Findings workflow:</strong> keep suspicious/high findings open until reviewed; ignore only confirmed false positives.</li>
                        <li><strong>Graph workflow:</strong> use Security Only or Code Quality Only first, then View in Graph from findings.</li>
                        <li><strong>Self-scanner baseline:</strong> this plugin excludes its own scanner/signature files by default to prevent false positives. Developers can enable self-scan with the <code>wpig_scan_self_plugin</code> filter.</li>
                    </ul>
                </div>
            </section>

            <section class="wpig-tab-panel" data-panel="settings">
                <div class="wpig-panel">
                    <h2>Settings</h2>
                    <p class="wpig-muted">This MVP runs locally in WordPress custom tables. Future settings can include scheduled scans, local Cytoscape vendor mode, YARA rules path, Neo4j sync, and notification emails.</p>
                </div>
            </section>
        </div>
    </div>
<?php }

add_action('rest_api_init', function () {
    register_rest_route('wpig/v1', '/stats', ['methods'=>'GET','callback'=>'wpig_rest_stats','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/graph', ['methods'=>'GET','callback'=>'wpig_rest_graph','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/scan', ['methods'=>'POST','callback'=>'wpig_rest_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/malware-scan', ['methods'=>'POST','callback'=>'wpig_rest_malware_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/code-quality-scan', ['methods'=>'POST','callback'=>'wpig_rest_code_quality_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/media-scan', ['methods'=>'POST','callback'=>'wpig_rest_media_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/surface-scan', ['methods'=>'POST','callback'=>'wpig_rest_surface_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/root-config-scan', ['methods'=>'POST','callback'=>'wpig_rest_root_config_scan','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/scanner-status', ['methods'=>'GET','callback'=>'wpig_rest_scanner_status','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/installer-resources', ['methods'=>'GET','callback'=>'wpig_rest_installer_resources','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/dependency-status', ['methods'=>'GET','callback'=>'wpig_rest_dependency_status','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/install-composer', ['methods'=>'POST','callback'=>'wpig_rest_install_composer','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/findings', ['methods'=>'GET','callback'=>'wpig_rest_findings','permission_callback'=>'wpig_can_manage']);
    register_rest_route('wpig/v1', '/finding-status', ['methods'=>'POST','callback'=>'wpig_rest_finding_status','permission_callback'=>'wpig_can_manage']);
});

function wpig_can_manage() { return current_user_can('manage_options'); }

function wpig_rest_stats() {
    global $wpdb; $t = wpig_tables();
    return rest_ensure_response([
        'nodes'=>(int)$wpdb->get_var("SELECT COUNT(*) FROM {$t['nodes']}"),
        'edges'=>(int)$wpdb->get_var("SELECT COUNT(*) FROM {$t['edges']}"),
        'findings'=>(int)$wpdb->get_var("SELECT COUNT(*) FROM {$t['findings']} WHERE status='open'"),
        'high_findings'=>(int)$wpdb->get_var("SELECT COUNT(*) FROM {$t['findings']} WHERE status='open' AND severity IN ('high','critical')"),
    ]);
}

function wpig_node_format($n) {
    $props = json_decode($n['properties'] ?: '{}', true);
    return ['data'=>['id'=>$n['uid'],'label'=>$n['label'],'type'=>$n['node_type'],'objectId'=>$n['object_id'],'objectType'=>$n['object_type'],'url'=>$n['url'],'properties'=>is_array($props)?$props:[]]];
}

function wpig_edge_format($e) {
    $props = json_decode($e['properties'] ?: '{}', true);
    return ['data'=>['id'=>$e['uid'],'source'=>$e['source_uid'],'target'=>$e['target_uid'],'label'=>$e['label'] ?: $e['edge_type'],'type'=>$e['edge_type'],'weight'=>(float)$e['weight'],'properties'=>is_array($props)?$props:[]]];
}

function wpig_rest_graph(WP_REST_Request $req) {
    global $wpdb; $t = wpig_tables();
    $limit = max(50, min(absint($req->get_param('limit') ?: 700), 1200));
    $focus = sanitize_text_field($req->get_param('focus_uid') ?: '');

    if ($focus) {
        // Tight focus mode:
        // Show only the selected finding, its directly connected nodes, and the parent folder path
        // for affected files. This prevents the graph from expanding into a noisy neighborhood.
        $direct_edges = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$t['edges']} WHERE source_uid=%s OR target_uid=%s LIMIT 120", $focus, $focus),
            ARRAY_A
        );

        $uids = [$focus];
        foreach ($direct_edges as $e) {
            $uids[] = $e['source_uid'];
            $uids[] = $e['target_uid'];
        }

        $uids = array_values(array_unique($uids));
        $ph = implode(',', array_fill(0, count($uids), '%s'));
        $direct_nodes = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$t['nodes']} WHERE uid IN ($ph)", $uids),
            ARRAY_A
        );

        $extra_nodes = [];
        $extra_edges = [];
        $node_by_uid = [];

        foreach ($direct_nodes as $n) {
            // Add editor URL and keep direct node.
            $props = json_decode($n['properties'] ?: '{}', true);
            if (($n['node_type'] ?? '') === 'file' && !empty($props['path'])) {
                $props['editor_url'] = wpig_graph_file_editor_url($props['path']);
                $n['properties'] = wp_json_encode($props);
            }
            $node_by_uid[$n['uid']] = $n;

            // Add root/path chain only for affected file nodes.
            if (($n['node_type'] ?? '') !== 'file') {
                continue;
            }

            $relative = $props['path'] ?? '';
            if (!$relative) {
                continue;
            }

            $parent_nodes = wpig_path_parent_nodes_for_file($relative);
            $previous = '';

            foreach ($parent_nodes as $pn) {
                $extra_nodes[$pn['uid']] = [
                    'uid' => $pn['uid'],
                    'node_type' => 'folder',
                    'label' => $pn['label'],
                    'object_id' => null,
                    'object_type' => 'folder',
                    'url' => null,
                    'properties' => wp_json_encode(['path'=>$pn['path']]),
                ];

                if (!empty($pn['parent_uid'])) {
                    $extra_edges['edge:' . md5($pn['parent_uid'] . ':contains:' . $pn['uid'])] = [
                        'uid' => 'edge:' . md5($pn['parent_uid'] . ':contains:' . $pn['uid']),
                        'source_uid' => $pn['parent_uid'],
                        'target_uid' => $pn['uid'],
                        'edge_type' => 'contains',
                        'label' => 'Contains',
                        'weight' => 1,
                        'properties' => null,
                    ];
                }

                $previous = $pn['uid'];
            }

            if ($previous) {
                $extra_edges['edge:' . md5($previous . ':contains:' . $n['uid'])] = [
                    'uid' => 'edge:' . md5($previous . ':contains:' . $n['uid']),
                    'source_uid' => $previous,
                    'target_uid' => $n['uid'],
                    'edge_type' => 'contains',
                    'label' => 'Contains',
                    'weight' => 1,
                    'properties' => null,
                ];
            }
        }

        $edge_by_uid = [];
        foreach ($direct_edges as $e) {
            $edge_by_uid[$e['uid']] = $e;
        }

        $nodes = array_values(array_merge($extra_nodes, $node_by_uid));
        $edges = array_values(array_merge($extra_edges, $edge_by_uid));

        return rest_ensure_response([
            'nodes' => array_map('wpig_node_format', $nodes),
            'edges' => array_map('wpig_edge_format', $edges),
            'focusUid' => $focus,
            'focused' => true,
        ]);
    }

    $nodes = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$t['nodes']} ORDER BY CASE node_type WHEN 'finding' THEN 1 WHEN 'duplicate_group' THEN 2 WHEN 'refactor_opportunity' THEN 3 WHEN 'malware_indicator' THEN 4 WHEN 'file' THEN 5 ELSE 6 END, id DESC LIMIT %d", $limit), ARRAY_A);
    $uids = array_map(fn($n)=>$n['uid'], $nodes);
    if (!$uids) return rest_ensure_response(['nodes'=>[],'edges'=>[],'focusUid'=>'']);
    $ph = implode(',', array_fill(0, count($uids), '%s'));
    $edges = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$t['edges']} WHERE source_uid IN ($ph) AND target_uid IN ($ph) LIMIT %d", array_merge($uids, $uids, [$limit*2])), ARRAY_A);
    return rest_ensure_response(['nodes'=>array_map('wpig_node_format',$nodes),'edges'=>array_map('wpig_edge_format',$edges),'focusUid'=>'']);
}

function wpig_rest_scan() {
    @set_time_limit(180);
    return rest_ensure_response(['success'=>true,'summary'=>wpig_run_site_graph_scan()]);
}

function wpig_rest_malware_scan(WP_REST_Request $req) {
    @set_time_limit(240);
    return rest_ensure_response(['success'=>true,'summary'=>wpig_run_malware_scan($req->get_param('engines'), $req->get_param('paths'))]);
}

function wpig_rest_code_quality_scan(WP_REST_Request $req) {
    @set_time_limit(240);
    return rest_ensure_response(['success'=>true,'summary'=>wpig_run_code_quality_scan($req->get_param('paths'))]);
}

function wpig_rest_media_scan(WP_REST_Request $req) {
    @set_time_limit(180);
    return rest_ensure_response(['success'=>true,'summary'=>wpig_run_media_scan(['large_kb'=>$req->get_param('large_kb')])]);
}


function wpig_rest_root_config_scan(WP_REST_Request $req) {
    @set_time_limit(240);
    return rest_ensure_response([
        'success'=>true,
        'summary'=>wpig_run_root_config_scan((bool)$req->get_param('include_core'))
    ]);
}

function wpig_rest_surface_scan(WP_REST_Request $req) {
    @set_time_limit(120);
    return rest_ensure_response(['success'=>true,'summary'=>wpig_run_surface_scan($req->get_param('checks'))]);
}

function wpig_rest_scanner_status() {
    return rest_ensure_response(wpig_scanner_availability());
}

function wpig_rest_installer_resources() {
    return rest_ensure_response([
        'availability' => wpig_scanner_availability(),
        'dependencies' => wpig_dependency_status(),
        'commands' => wpig_resource_install_commands(),
        'notes' => [
            'System package installation usually requires SSH/root or sudo access.',
            'Shared hosting may block shell_exec, YARA, ClamAV, and Maldet.',
            'The built-in malware scanner and code quality scanner work without system packages.',
            'AST scanning requires Composer dependency nikic/php-parser.'
        ],
    ]);
}

function wpig_rest_findings(WP_REST_Request $req) {
    global $wpdb; $t = wpig_tables();
    $status = sanitize_key($req->get_param('status') ?: 'open');
    $filter = sanitize_key($req->get_param('filter') ?: 'all');

    $where = "status=%s";
    $params = [$status];

    if ($filter === 'malware') {
        $where .= " AND (finding_type IN ('file_security','yara_scan','clamav_scan','maldet_scan','advanced_regex_scan','advanced_ast_scan','advanced_entropy_scan','advanced_advanced_scan') OR finding_type LIKE %s OR evidence LIKE %s)";
        $params[] = '%malware%';
        $params[] = '%"scanner":"advanced%';
    } elseif ($filter === 'code_quality') {
        $where .= " AND (finding_type = %s OR evidence LIKE %s)";
        $params[] = 'code_quality_scan';
        $params[] = '%"scanner":"code_quality"%';
    } elseif ($filter === 'media') {
        $where .= " AND (finding_type = %s OR evidence LIKE %s)";
        $params[] = 'media_scan';
        $params[] = '%"scanner":"media"%';
    } elseif ($filter === 'surface') {
        $where .= " AND (finding_type = %s OR evidence LIKE %s)";
        $params[] = 'surface_scan';
        $params[] = '%"scanner":"surface"%';
    } elseif ($filter === 'root_config') {
        $where .= " AND (finding_type = %s OR evidence LIKE %s)";
        $params[] = 'root_config';
        $params[] = '%"scanner":"root_config"%';
    } elseif ($filter === 'high') {
        $where .= " AND severity IN ('high','critical')";
    }

    $sql = "SELECT * FROM {$t['findings']} WHERE {$where} ORDER BY score DESC, id DESC LIMIT 220";
    $rows = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
    foreach ($rows as &$r) $r['evidence'] = json_decode($r['evidence'] ?: '{}', true);
    return rest_ensure_response($rows);
}

function wpig_rest_finding_status(WP_REST_Request $req) {
    global $wpdb; $t = wpig_tables();
    $uid = sanitize_text_field($req->get_param('uid'));
    $status = sanitize_key($req->get_param('status'));
    if (!in_array($status, ['open','reviewed','ignored'], true)) $status = 'open';
    if (!$uid) return new WP_Error('wpig_missing_uid', 'Missing finding UID.', ['status'=>400]);
    $wpdb->update($t['findings'], ['status'=>$status,'updated_at'=>current_time('mysql')], ['uid'=>$uid]);
    return rest_ensure_response(['success'=>true]);
}
