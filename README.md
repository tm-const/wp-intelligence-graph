# WP Intelligence Graph

> WordPress admin plugin for mapping site relationships, scanning suspicious code/files, reviewing code quality, and visualizing findings as an interactive knowledge graph.

WP Intelligence Graph turns a WordPress environment into an investigator-friendly dashboard. It scans `wp-content` paths, maps content relationships, surfaces suspicious files, detects code-quality risks, checks media metadata gaps, and renders results in a Cytoscape.js graph with focused issue isolation.

---

## Table of Contents

1. [About The Project](#about-the-project)
2. [Built With](#built-with)
3. [Core Features](#core-features)
4. [Screens and Admin Tabs](#screens-and-admin-tabs)
5. [Scanner Coverage](#scanner-coverage)
6. [Graph Explorer](#graph-explorer)
7. [Findings System](#findings-system)
8. [Getting Started](#getting-started)
9. [Installation](#installation)
10. [Recommended Setup](#recommended-setup)
11. [Optional Scanner Engines](#optional-scanner-engines)
12. [Configuration](#configuration)
13. [How The Plugin Works](#how-the-plugin-works)
14. [Database Tables](#database-tables)
15. [Key Files and Code Architecture](#key-files-and-code-architecture)
16. [Security Model](#security-model)
17. [Performance Notes](#performance-notes)
18. [Troubleshooting](#troubleshooting)
19. [Roadmap](#roadmap)
20. [Developer Notes](#developer-notes)
21. [License](#license)

---

## About The Project

WP Intelligence Graph is a WordPress security and code intelligence plugin designed to help site owners, developers, and maintainers understand what exists inside a WordPress environment.

It focuses on four major problems:

- **Security visibility**: suspicious PHP, malware indicators, obfuscation, shell execution, injected scripts, risky root/config files.
- **Code quality visibility**: duplicate symbols, large functions, SQL preparation risks, nonce/capability review, unsafe file operations, legacy PHP practices.
- **Content/site structure visibility**: posts, pages, internal links, external domains, taxonomy relationships, media references.
- **Graph-based investigation**: nodes and edges help isolate a finding back to the affected file, scanner indicator, plugin/theme, or parent context.

The plugin is built to run from the WordPress admin and store scan output locally in custom database tables.

---

## Built With

- **PHP** — WordPress plugin runtime and scanners.
- **WordPress REST API** — Admin AJAX-style scan and dashboard endpoints.
- **MySQL / `$wpdb`** — Custom graph, edge, scan, and finding storage.
- **Cytoscape.js** — Interactive graph visualization.
- **PHP tokenizer** — Symbol and code-quality analysis through `token_get_all()`.
- **Optional Composer packages**:
  - `nikic/php-parser` for deeper AST analysis when installed.
- **Optional server scanners**:
  - YARA
  - ClamAV
  - Linux Malware Detect / Maldet

No external charting library is required for the Overview dashboard; charts are lightweight CSS/SVG-style UI components.

---

## Core Features

### 1. Overview Dashboard

The Overview tab acts as the main executive summary.

It includes:

- KPI cards:
  - Total findings
  - Critical/high findings
  - Malware findings
  - Code quality findings
  - Root/config findings
  - Exposure findings
- Findings by Scanner donut chart
- Severity breakdown bars
- Priority finding cards
- Scanner coverage cards
- Finding queue cards

### 2. Graph Explorer

The graph maps:

- Content nodes
- File nodes
- Code symbol nodes
- Malware indicator nodes
- Code quality/refactor nodes
- Plugin/theme nodes
- External/internal URL nodes
- Root/config nodes when enabled
- Exposure nodes such as REST, cron, scripts, and ports

The graph supports:

- Cached graph loading
- Loading overlay
- Light/dark graph theme
- Reset Graph
- Findings side panel
- Node filters
- Focused finding isolation
- Expanded color key legend

### 3. Malware Scanner

The malware scanner checks for suspicious indicators such as:

- `eval()`
- `base64_decode()`
- `gzinflate()`
- `str_rot13()`
- `shell_exec()`
- `system()`
- `passthru()`
- `proc_open()`
- `popen()`
- suspicious webshell behavior
- obfuscation patterns
- risky callbacks
- encoded payloads
- external payload hosts

It supports:

- Built-in indicator scanning
- Optional YARA
- Optional ClamAV
- Optional Maldet
- Modular advanced scanner layer

### 4. Code Quality Scanner

The code-quality scanner reviews PHP files for:

- duplicate functions/classes/methods
- repeated normalized function bodies
- large functions
- TODO/FIXME/HACK comments
- direct superglobal access review
- SQL preparation risks
- missing nonce/capability checks
- escaping/sanitization review
- REST/AJAX exposure checks
- unsafe file operations
- hardcoded secrets/API keys
- debug/error leakage
- performance smells
- exposed backup/archive/env/dependency files
- legacy PHP practices

### 5. Media Scanner

The media scanner reviews WordPress attachments for:

- missing alt text
- missing image titles
- missing descriptions/captions
- large file sizes
- large dimensions
- where possible, media usage context

Media cards intentionally use media-library actions instead of WP code editor links.

### 6. Root / Config Scanner

Root/config checks review:

- `wp-config.php`
- `.htaccess`
- root PHP files
- unknown root PHP files
- exposed `.env`, `.sql`, `.bak`, `.zip`, `.log`, `.old` files
- optional core paths:
  - `wp-admin`
  - `wp-includes`

Root/config nodes are hidden by default in the graph unless selected from Node Filters.

### 7. Exposure Scanner

Exposure checks include:

- WordPress cron jobs
- third-party JavaScript scripts
- REST API endpoints
- open port checks where supported
- surface-level security review nodes

---

## Screens and Admin Tabs

### Overview

Primary dashboard for:

- scan summary
- finding counts
- priority finding queue
- severity breakdown
- quick scanner queues
- scan coverage

### Graph Explorer

Interactive Cytoscape graph for visual investigation.

Important controls:

- **Findings**: opens graph findings side panel.
- **Light / Dark**: changes graph theme.
- **Reset Graph**: restores the default scan-enabled full graph view.
- **Node Filters**: shows/hides node groups.

### Findings

Detailed findings list with filters:

- All Open
- Malware
- Code Quality
- Media
- Exposure
- Root / Config
- High/Critical

### Malware Scanner

Runs security scans and displays scanner availability.

### Code Quality

Runs code review and PHP quality checks.

### Media Scanner

Reviews attachment metadata and media optimization issues.

### Installer

Checks optional dependencies and scanner resources.

### Settings

Scanner limits and plugin behavior settings.

---

## Scanner Coverage

### Default Scan Paths

The default scanner setup focuses on:

```text
wp-content/plugins
wp-content/themes
wp-content/uploads
wp-content/mu-plugins
```

### Optional Scan Paths

Optional paths include:

```text
WordPress Root Files
WordPress Core Files
```

`WordPress Root Files` is **not enabled by default** because root/config scans can generate a lot of review findings and should be run intentionally.

### Self-Scanner Baseline

The plugin excludes itself by default:

```text
wp-content/plugins/wp-intelligence-graph/*
```

This avoids false positives from scanner signatures, such as:

```text
eval
base64_decode
shell_exec
gzinflate
system
passthru
```

To enable self-scanning during development:

```php
add_filter('wpig_scan_self_plugin', '__return_true');
```

---

## Graph Explorer

### Node Groups

The graph supports the following color-key groups:

- Content
- Files
- Code Symbols
- Code Quality
- Duplicate / Refactor
- Findings
- Malware
- Root / Config
- Exposure
- Plugin / Theme
- URLs / Domains
- Media

### Default Graph Visibility

Initial graph view shows scan-enabled node types only.

Hidden by default:

- root
- root_file
- root_config
- folder path context

These can still be enabled from Node Filters or **Check All**.

### Focused Finding View

Clicking a finding can isolate:

```text
finding node
affected file/code node
direct scanner/indicator node
parent path context
```

### Reset Graph

Reset Graph:

- clears focused state
- restores default scan-enabled node filters
- reloads graph if dirty
- applies full graph layout
- centers and fits visible nodes

### Graph Performance Optimizations

The graph includes:

- graph cache state
- dirty state tracking
- loading overlay
- layout only when needed
- visible-node layout
- large graph label suppression
- reduced pointer-event impact while scrolling
- light/dark themes

---

## Findings System

Each finding can include:

- UID
- scanner type
- severity
- score
- title
- description
- source file
- line number
- evidence metadata
- graph node references
- editor URL when available

### Severity Levels

- Critical
- High
- Medium
- Low
- Info

### Finding Categories

- Malware
- Code Quality
- Root / Config
- Exposure
- Media
- Other

### WP Editor Links

Non-media findings can include an **Open in WP Editor** action when the affected file is inside:

```text
wp-content/plugins/...
wp-content/themes/...
```

Media findings intentionally do not use WP Editor links.

---

## Getting Started

### Prerequisites

Required:

- WordPress 6.x recommended
- PHP 8.x recommended
- MySQL/MariaDB
- Admin user with `manage_options`

Optional:

- Composer
- YARA
- ClamAV
- Maldet
- `nikic/php-parser`

### Recommended PHP Settings

For larger scans, consider:

```ini
memory_limit = 256M or higher
max_execution_time = 240 or higher
```

For very large sites, background/batched scanning is recommended as a future enhancement.

---

## Installation

### Upload Through WordPress Admin

1. Download the plugin ZIP.
2. Go to:

```text
WordPress Admin → Plugins → Add New → Upload Plugin
```

3. Upload the ZIP.
4. Activate the plugin.
5. Open:

```text
WP Intelligence Graph
```

6. Run:

```text
Run Site Graph Scan
```

### Manual Install

1. Extract the plugin folder.
2. Upload it to:

```text
wp-content/plugins/wp-intelligence-graph/
```

3. Activate from WordPress Admin.
4. Visit the plugin admin page.

---

## Recommended Setup

Recommended first run:

1. Open **Overview**.
2. Click **Run Site Graph Scan**.
3. Wait for the progress panel to complete.
4. Review the Overview KPI cards.
5. Click into:
   - Malware queue
   - Code Quality queue
   - Root / Config queue
   - Exposure queue
6. Open **Graph Explorer** to inspect relationships.

### Recommended Default Scanner Options

Default enabled:

```text
wp-content/plugins
wp-content/themes
wp-content/uploads
wp-content/mu-plugins
```

Default disabled:

```text
WordPress Root Files
WordPress Core Files
```

Run root/core scans intentionally when investigating deeper compromise.

---

## Optional Scanner Engines

### YARA

YARA can be used for rule-based malware scanning when the `yara` command is installed on the server.

### ClamAV

ClamAV can be used when `clamscan` is available.

### Maldet

Linux Malware Detect can be used when `maldet` is installed.

### Server Command Execution

Optional engines require server command execution. Keep this restricted to trusted admin users only.

---

## Configuration

### Self-Scanning

Disabled by default:

```php
add_filter('wpig_scan_self_plugin', '__return_true');
```

### Composer Installer

If the plugin includes a Composer installer button, it should be gated behind an explicit constant such as:

```php
define('WPIG_ALLOW_COMPOSER_INSTALL', true);
```

Recommended production behavior:

```php
define('WPIG_ALLOW_COMPOSER_INSTALL', false);
```

### Scan Limits

The plugin uses scan limits to avoid overloading wp-admin.

Typical limits include:

- built-in malware scan file limits
- code-quality file limits
- advanced scanner file limits
- sensitive file scan limits

For very large sites, increase cautiously.

---

## How The Plugin Works

### Full Site Scan Flow

`Run Site Graph Scan` runs non-media scans:

1. Site graph scan
2. Malware scan
3. Code quality scan
4. Root/config scan
5. Exposure scan

Media scan is intentionally separate.

### Graph Data Flow

```text
WordPress content/files
→ scanners
→ custom DB tables
→ REST endpoints
→ Cytoscape.js graph
→ focused investigation views
```

### Finding Flow

```text
Scanner match
→ finding row
→ finding node
→ edge to affected file/code node
→ edge to scanner/indicator node
→ Overview / Findings / Graph Explorer
```

---

## Database Tables

The plugin creates custom tables similar to:

```text
wp_wpig_nodes
wp_wpig_edges
wp_wpig_findings
wp_wpig_scans
```

### Nodes

Stores graph nodes:

- posts
- pages
- users
- terms
- files
- code symbols
- findings
- scanner indicators
- plugin/theme nodes
- root/config nodes
- exposure nodes

### Edges

Stores graph relationships:

- contains
- has finding
- classified as
- internal link
- external domain link
- symbol belongs to file
- plugin/theme ownership

### Findings

Stores scanner findings:

- severity
- score
- scanner type
- source file
- line number
- evidence JSON
- status

### Scans

Stores scan history and scan summaries.

---

## Key Files and Code Architecture

### Main Plugin File

```text
wp-intelligence-graph.php
```

Contains:

- plugin bootstrap
- activation logic
- custom table creation
- REST route registration
- admin UI rendering
- scan orchestration
- graph/finding helpers
- root/config scanner
- media scanner
- exposure scanner
- code quality scanner logic

### Scanner Classes

```text
scanner/FileCollector.php
```

Collects files for advanced scanners and excludes this plugin by default.

```text
scanner/RegexScanner.php
```

Pattern-based scanning for suspicious strings and behaviors.

```text
scanner/ASTScanner.php
```

AST-aware scanning layer when parser support is available.

```text
scanner/EntropyScanner.php
```

Detects high-entropy/obfuscated strings and encoded payload indicators.

```text
scanner/RiskEngine.php
```

Scores findings based on scanner indicators, severity, and contextual risk.

```text
scanner/ScanManager.php
```

Coordinates advanced scanner execution.

### Admin JavaScript

```text
admin/js/admin.js
```

Handles:

- tab navigation
- scan actions
- overview dashboard hydration
- graph rendering
- Cytoscape setup
- graph loading cache
- graph filters
- graph findings panel
- result dashboards
- media/finding UI actions

### Admin CSS

```text
admin/css/admin.css
```

Handles:

- dashboard layout
- scan progress UI
- graph theme
- node filter layout
- findings cards
- overview charts
- responsive admin UI

### YARA Rules

```text
rules/wpig-default.yar
```

Default YARA rules for optional YARA scanning.

---

## Security Model

### Capability Checks

Admin actions should require:

```php
current_user_can('manage_options')
```

### Non-Destructive Scanning

The scanner records findings but should not automatically delete or quarantine files.

### Safe Defaults

- self-scanning disabled
- root files not scanned by default
- core files optional
- optional command scanners disabled unless installed/available
- Composer installer should require explicit opt-in

### Sensitive Findings

Some findings are review-only, such as:

- DB credential constants inside `wp-config.php`
- WordPress auth keys/salts
- expected scanner signatures
- known root files

Review before making changes.

---

## Performance Notes

### Why Large Sites Can Lag

Large graphs can become expensive because of:

- many nodes
- many edges
- labels
- layout calculations
- scroll/pointer events inside Cytoscape

### Optimizations Included

- graph cache
- graph dirty flags
- visible-node layout
- large graph label suppression
- pointer events disabled unless hovering graph card
- layout only when needed
- loading overlays
- scan progress state
- graph fit/center after layout

### Recommended Workflow

For large sites:

1. Run full scan.
2. Review Overview first.
3. Use Findings filters.
4. Click specific findings to inspect focused graph views.
5. Use full graph only for broader relationship review.

---

## Troubleshooting

### Findings Count Shows 0 After Scan

Try:

1. Refresh Overview.
2. Open Findings → Refresh Findings.
3. Run the specific scanner again.
4. Confirm custom tables were created.

### Malware Findings From This Plugin

The plugin excludes itself by default to prevent scanner self-signature false positives.

If you enabled self-scanning, you may see references to:

```text
eval
base64_decode
shell_exec
YARA rules
RegexScanner patterns
RiskEngine weights
```

### Graph Looks Flat or Unstructured

Use:

```text
Reset Graph
```

The graph should apply the full visible-layout routine and fit nodes into view.

### Graph Freezes Scrolling

The plugin reduces pointer event load, but very large graphs may still be expensive.

Use:

- Findings filters
- focused graph views
- default node filters
- reset graph only when needed

### WP Editor Link Missing

WP Editor links are only generated for files under:

```text
wp-content/plugins/...
wp-content/themes/...
```

They are not shown for media findings.

### Optional Scanners Not Available

Check the Installer tab.

YARA, ClamAV, and Maldet only work when installed on the server and available to PHP.

---

## Roadmap

Planned improvements:

- Background scan queue
- Batched scans for very large sites
- Core checksum verification
- File integrity baseline
- AI-assisted finding explanations
- AI-assisted remediation suggestions
- Export findings to CSV/JSON
- Export graph snapshots
- Scheduled scans
- Email alerts
- More advanced dependency/supply-chain checks
- Better REST endpoint risk classification
- Dedicated root/config report page
- Optional Neo4j/Memgraph exporter

---

## Developer Notes

### Recommended Development Flow

1. Make changes locally.
2. Validate PHP:

```bash
php -l wp-intelligence-graph.php
php -l scanner/*.php
```

3. Validate JavaScript:

```bash
node --check admin/js/admin.js
```

4. Zip the plugin folder.
5. Upload to a staging WordPress site.
6. Run scans on staging before production.

### Suggested Branch Names

```text
feature/overview-dashboard
feature/root-config-scan
feature/graph-performance
feature/code-quality-scanner
fix/graph-layout-cache
fix/malware-self-baseline
```

### Suggested Commit Format

```text
feat: add root config scanner
fix: prevent graph reload on tab switch
perf: cache graph layout after initial render
docs: add advanced README
```

---

## License

This plugin is provided as a custom WordPress admin tool. Add the final license here before publishing publicly.

Recommended open-source options:

- GPL-2.0-or-later for WordPress.org compatibility
- MIT for permissive private/public repository usage

---

## Acknowledgments

- WordPress Plugin API
- WordPress REST API
- Cytoscape.js
- YARA
- ClamAV
- Linux Malware Detect
- `nikic/php-parser`
- Best README Template structure inspiration

---

## Status

Current build focus:

```text
WP Intelligence Graph v0.8.4 modular series
Security scanner + code quality scanner + knowledge graph dashboard
```

This README is intended for GitHub/project documentation and can live next to the WordPress `readme.txt`.
