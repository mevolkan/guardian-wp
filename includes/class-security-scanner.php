<?php
defined( 'ABSPATH' ) || exit;

/**
 * Scans for common WordPress vulnerabilities:
 *  - Outdated core, plugins, themes
 *  - Known weak configurations
 *  - Suspicious file patterns (basic)
 *  - User enumeration exposure
 */
class WPG_Security_Scanner {

    private WPG_API_Client $client;

    // Files that should never be publicly readable
    private const SENSITIVE_FILES = [
        'wp-config.php',
        '.env',
        'xmlrpc.php',
        'wp-admin/install.php',
    ];

    // PHP functions commonly used in malware
    private const SUSPICIOUS_FUNCTIONS = [
        'eval(base64_decode',
        'system($_',
        'exec($_',
        'passthru($_',
        'shell_exec($_',
        'assert(base64',
        'preg_replace.*\/e',
        'create_function',
    ];

    public function __construct( WPG_API_Client $client ) {
        $this->client = $client;
        add_action( 'wpg_security_scan', [ $this, 'run_scan' ] );

        // Trigger a scan on plugin/theme update
        add_action( 'upgrader_process_complete', [ $this, 'run_scan' ], 10, 0 );
    }

    public function run_scan(): void {
        $vulnerabilities = [];

        $vulnerabilities = array_merge( $vulnerabilities,
            $this->check_core_version(),
            $this->check_plugins(),
            $this->check_themes(),
            $this->check_configuration(),
            $this->check_user_enumeration(),
            $this->check_file_permissions(),
            $this->scan_for_suspicious_code()
        );

        if ( empty( $vulnerabilities ) ) {
            return;
        }

        $this->client->ingest( [
            'site_info' => [
                'wp_version'  => get_bloginfo( 'version' ),
                'php_version' => PHP_VERSION,
            ],
            'vulnerabilities' => $vulnerabilities,
            'metrics' => $this->collect_metrics(),
        ] );
    }

    // ── Core version check ────────────────────────────────────────────────────

    private function check_core_version(): array {
        $current = get_bloginfo( 'version' );
        // Compare against the update API
        $update = get_site_transient( 'update_core' );
        if ( ! $update ) {
            wp_version_check();
            $update = get_site_transient( 'update_core' );
        }

        if ( isset( $update->updates ) ) {
            foreach ( $update->updates as $u ) {
                if ( 'upgrade' === $u->response ) {
                    return [ [
                        'vuln_type'           => 'outdated_core',
                        'severity'            => 'high',
                        'title'               => "WordPress core is outdated ({$current})",
                        'description'         => "Update available: {$u->version}. Outdated core exposes the site to known CVEs.",
                        'affected_component'  => 'wordpress-core',
                        'affected_version'    => $current,
                        'details'             => [ 'latest_version' => $u->version ],
                    ] ];
                }
            }
        }
        return [];
    }

    // ── Plugin checks ─────────────────────────────────────────────────────────

    private function check_plugins(): array {
        $results = [];

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        $update  = get_site_transient( 'update_plugins' );
        if ( ! $update ) {
            wp_update_plugins();
            $update = get_site_transient( 'update_plugins' );
        }

        // Outdated plugins
        foreach ( $plugins as $slug => $data ) {
            if ( isset( $update->response[ $slug ] ) ) {
                $new_version = $update->response[ $slug ]->new_version;
                $results[]   = [
                    'vuln_type'           => 'outdated_plugin',
                    'severity'            => 'medium',
                    'title'               => "Plugin outdated: {$data['Name']}",
                    'description'         => "Running {$data['Version']}, latest is {$new_version}.",
                    'affected_component'  => $data['Name'],
                    'affected_version'    => $data['Version'],
                    'details'             => [
                        'slug'           => $slug,
                        'latest_version' => $new_version,
                    ],
                ];
            }
        }

        // Inactive plugins (attack surface)
        $active = get_option( 'active_plugins', [] );
        foreach ( $plugins as $slug => $data ) {
            if ( ! in_array( $slug, $active, true ) ) {
                $results[] = [
                    'vuln_type'           => 'inactive_plugin',
                    'severity'            => 'low',
                    'title'               => "Inactive plugin present: {$data['Name']}",
                    'description'         => 'Inactive plugins can still be exploited if they contain vulnerabilities. Consider removing unused plugins.',
                    'affected_component'  => $data['Name'],
                    'affected_version'    => $data['Version'],
                    'details'             => [ 'slug' => $slug ],
                ];
            }
        }

        return $results;
    }

    // ── Theme checks ──────────────────────────────────────────────────────────

    private function check_themes(): array {
        $results = [];
        $update  = get_site_transient( 'update_themes' );

        if ( $update && ! empty( $update->response ) ) {
            foreach ( $update->response as $slug => $data ) {
                $theme = wp_get_theme( $slug );
                if ( $theme->exists() ) {
                    $results[] = [
                        'vuln_type'           => 'outdated_theme',
                        'severity'            => 'medium',
                        'title'               => "Theme outdated: {$theme->get('Name')}",
                        'description'         => "Running {$theme->get('Version')}, latest is {$data['new_version']}.",
                        'affected_component'  => $theme->get( 'Name' ),
                        'affected_version'    => $theme->get( 'Version' ),
                        'details'             => [ 'slug' => $slug, 'latest_version' => $data['new_version'] ],
                    ];
                }
            }
        }

        return $results;
    }

    // ── Configuration checks ──────────────────────────────────────────────────

    private function check_configuration(): array {
        $results = [];

        // Debug mode left on in production
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $results[] = [
                'vuln_type'   => 'weak_config',
                'severity'    => 'medium',
                'title'       => 'WP_DEBUG is enabled',
                'description' => 'Debug mode exposes PHP errors to visitors. Disable in production.',
                'affected_component' => 'wp-config.php',
            ];
        }

        // File editing enabled
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
            $results[] = [
                'vuln_type'   => 'weak_config',
                'severity'    => 'medium',
                'title'       => 'Theme/plugin file editor is enabled',
                'description' => 'Set DISALLOW_FILE_EDIT to true in wp-config.php to prevent in-admin code editing.',
                'affected_component' => 'wp-config.php',
            ];
        }

        // Default admin username
        if ( username_exists( 'admin' ) ) {
            $results[] = [
                'vuln_type'   => 'weak_config',
                'severity'    => 'high',
                'title'       => 'Default "admin" username exists',
                'description' => 'The default "admin" username is a common brute-force target. Rename it.',
                'affected_component' => 'users',
            ];
        }

        // xmlrpc.php enabled
        if ( ! defined( 'XMLRPC_REQUEST' ) ) {
            $ping_url  = home_url( '/xmlrpc.php' );
            $response  = wp_remote_head( $ping_url, [ 'timeout' => 5 ] );
            $code      = wp_remote_retrieve_response_code( $response );
            if ( $code === 200 || $code === 405 ) {
                $results[] = [
                    'vuln_type'   => 'weak_config',
                    'severity'    => 'medium',
                    'title'       => 'XML-RPC is enabled',
                    'description' => 'XML-RPC can be abused for brute-force and DDoS amplification attacks. Disable if not needed.',
                    'affected_component' => 'xmlrpc.php',
                ];
            }
        }

        // PHP version
        $php = PHP_VERSION;
        if ( version_compare( $php, '8.1', '<' ) ) {
            $results[] = [
                'vuln_type'          => 'outdated_runtime',
                'severity'           => version_compare( $php, '7.4', '<' ) ? 'high' : 'medium',
                'title'              => "PHP {$php} is outdated",
                'description'        => 'PHP ' . $php . ' is end-of-life or approaching end-of-life. Upgrade to PHP 8.1+.',
                'affected_component' => 'php',
                'affected_version'   => $php,
            ];
        }

        return $results;
    }

    // ── User enumeration ──────────────────────────────────────────────────────

    private function check_user_enumeration(): array {
        $test_url = home_url( '/?author=1' );
        $response = wp_remote_get( $test_url, [ 'timeout' => 5, 'redirection' => 0 ] );
        $code     = wp_remote_retrieve_response_code( $response );

        if ( $code === 301 || $code === 302 ) {
            $location = wp_remote_retrieve_header( $response, 'location' );
            if ( strpos( $location, '/author/' ) !== false ) {
                return [ [
                    'vuln_type'   => 'user_enumeration',
                    'severity'    => 'medium',
                    'title'       => 'User enumeration via author archives is possible',
                    'description' => 'The site redirects ?author=1 to an author URL, leaking usernames. Block this at the server or firewall level.',
                    'affected_component' => 'author-archives',
                ] ];
            }
        }
        return [];
    }

    // ── File permission checks ────────────────────────────────────────────────

    private function check_file_permissions(): array {
        $results = [];
        $config  = ABSPATH . 'wp-config.php';

        if ( file_exists( $config ) ) {
            $perms = substr( sprintf( '%o', fileperms( $config ) ), -4 );
            if ( (int) $perms > 640 ) {
                $results[] = [
                    'vuln_type'          => 'weak_file_permission',
                    'severity'           => 'high',
                    'title'              => "wp-config.php permissions too permissive ({$perms})",
                    'description'        => 'wp-config.php should be 600 or 640. Current permissions allow too broad access.',
                    'affected_component' => 'wp-config.php',
                    'details'            => [ 'permissions' => $perms ],
                ];
            }
        }
        return $results;
    }

    // ── Suspicious code scan ──────────────────────────────────────────────────

    private function scan_for_suspicious_code(): array {
        $results  = [];
        $scan_dir = WP_CONTENT_DIR . '/uploads';

        if ( ! is_dir( $scan_dir ) ) {
            return [];
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $scan_dir, FilesystemIterator::SKIP_DOTS )
        );

        $scanned = 0;
        foreach ( $iterator as $file ) {
            if ( $file->isFile() && in_array( strtolower( $file->getExtension() ), [ 'php', 'php5', 'phtml' ], true ) ) {
                $content = @file_get_contents( $file->getPathname(), false, null, 0, 8192 );
                if ( false === $content ) continue;

                foreach ( self::SUSPICIOUS_FUNCTIONS as $pattern ) {
                    if ( stripos( $content, $pattern ) !== false ) {
                        $results[] = [
                            'vuln_type'          => 'suspicious_file',
                            'severity'           => 'critical',
                            'title'              => 'PHP file with suspicious code in /uploads',
                            'description'        => "Found '{$pattern}' in uploads directory — possible webshell or malware.",
                            'affected_component' => str_replace( ABSPATH, '', $file->getPathname() ),
                            'details'            => [ 'pattern' => $pattern ],
                        ];
                        break; // one finding per file
                    }
                }

                if ( ++$scanned >= 500 ) break; // limit scan depth
            }
        }

        return $results;
    }

    // ── Metrics collection ────────────────────────────────────────────────────

    private function collect_metrics(): array {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        return [
            [
                'metric_type' => 'active_plugins',
                'value'       => (float) count( get_option( 'active_plugins', [] ) ),
                'unit'        => 'count',
            ],
            [
                'metric_type' => 'total_plugins',
                'value'       => (float) count( get_plugins() ),
                'unit'        => 'count',
            ],
            [
                'metric_type' => 'total_users',
                'value'       => (float) count_users()['total_users'],
                'unit'        => 'count',
            ],
            [
                'metric_type' => 'php_version_num',
                'value'       => (float) PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
                'unit'        => 'version',
                'metadata'    => [ 'full' => PHP_VERSION ],
            ],
        ];
    }
}
