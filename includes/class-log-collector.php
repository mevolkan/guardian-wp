<?php
defined( 'ABSPATH' ) || exit;

/**
 * Intercepts PHP errors and WordPress debug log entries,
 * buffers them in a transient, and flushes to the server hourly.
 */
class WPG_Log_Collector {

    private WPG_API_Client $client;
    private const BUFFER_KEY  = 'wpg_log_buffer';
    private const BUFFER_LIMIT = 200; // max entries before auto-flush

    public function __construct( WPG_API_Client $client ) {
        $this->client = $client;

        // Hook into PHP error handler
        set_error_handler( [ $this, 'handle_php_error' ], E_ALL );

        // Hook into WordPress fatal error handler (WP 5.2+)
        add_filter( 'wp_fatal_error_handler_enabled', '__return_true' );

        // Hook into WordPress debug log via 'error_log' filter
        add_filter( 'wp_debug_log_file', [ $this, 'intercept_debug_log' ] );

        // Hook into wp_die for admin errors
        add_filter( 'wp_die_handler', [ $this, 'handle_wp_die' ] );

        // Listen for database errors
        add_action( 'wp_db_query_failed', [ $this, 'handle_db_error' ] );

        // Cron flush
        add_action( 'wpg_flush_logs', [ $this, 'flush' ] );

        // Also flush on shutdown if buffer is big
        add_action( 'shutdown', [ $this, 'maybe_flush_on_shutdown' ] );
    }

    // ── PHP error handler ─────────────────────────────────────────────────────

    public function handle_php_error( int $errno, string $errstr, string $errfile = '', int $errline = 0 ): bool {
        $level = $this->errno_to_level( $errno );
        $this->buffer( [
            'level'   => $level,
            'message' => $errstr,
            'source'  => 'php',
            'context' => [
                'file'  => str_replace( ABSPATH, '', $errfile ),
                'line'  => $errline,
                'errno' => $errno,
            ],
            'timestamp' => gmdate( 'c' ),
        ] );

        // Allow default PHP error handler to continue
        return false;
    }

    // ── WordPress database error ──────────────────────────────────────────────

    public function handle_db_error(): void {
        global $wpdb;
        if ( $wpdb->last_error ) {
            $this->buffer( [
                'level'   => 'ERROR',
                'message' => $wpdb->last_error,
                'source'  => 'wordpress',
                'context' => [ 'query' => $wpdb->last_query ],
                'timestamp' => gmdate( 'c' ),
            ] );
        }
    }

    // ── wp_die handler (captures error messages in admin) ─────────────────────

    public function handle_wp_die( callable $handler ): callable {
        return function ( $message, $title = '', $args = [] ) use ( $handler ) {
            if ( is_string( $message ) && strlen( $message ) > 0 ) {
                $this->buffer( [
                    'level'   => 'ERROR',
                    'message' => wp_strip_all_tags( $message ),
                    'source'  => 'wordpress',
                    'context' => [ 'title' => $title ],
                    'timestamp' => gmdate( 'c' ),
                ] );
            }
            $handler( $message, $title, $args );
        };
    }

    // ── WordPress debug.log intercept ─────────────────────────────────────────

    public function intercept_debug_log( string $path ): string {
        // We're not changing the path, just hooking in to detect it's enabled.
        // Real log lines are caught via error_handler above.
        return $path;
    }

    // ── Buffer management ─────────────────────────────────────────────────────

    private function buffer( array $entry ): void {
        $buffer = get_transient( self::BUFFER_KEY ) ?: [];
        $buffer[] = $entry;
        set_transient( self::BUFFER_KEY, $buffer, HOUR_IN_SECONDS * 2 );

        if ( count( $buffer ) >= self::BUFFER_LIMIT ) {
            $this->flush();
        }
    }

    public function flush(): void {
        $buffer = get_transient( self::BUFFER_KEY );
        if ( empty( $buffer ) ) {
            return;
        }

        delete_transient( self::BUFFER_KEY );

        $this->client->ingest( [
            'site_info' => [
                'wp_version'  => get_bloginfo( 'version' ),
                'php_version' => PHP_VERSION,
            ],
            'logs' => $buffer,
        ] );
    }

    public function maybe_flush_on_shutdown(): void {
        $buffer = get_transient( self::BUFFER_KEY ) ?: [];
        if ( count( $buffer ) >= 10 ) {
            $this->flush();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function errno_to_level( int $errno ): string {
        $map = [
            E_ERROR             => 'ERROR',
            E_WARNING           => 'WARNING',
            E_PARSE             => 'ERROR',
            E_NOTICE            => 'NOTICE',
            E_CORE_ERROR        => 'ERROR',
            E_CORE_WARNING      => 'WARNING',
            E_COMPILE_ERROR     => 'ERROR',
            E_COMPILE_WARNING   => 'WARNING',
            E_USER_ERROR        => 'ERROR',
            E_USER_WARNING      => 'WARNING',
            E_USER_NOTICE       => 'NOTICE',
            E_STRICT            => 'NOTICE',
            E_RECOVERABLE_ERROR => 'ERROR',
            E_DEPRECATED        => 'WARNING',
            E_USER_DEPRECATED   => 'WARNING',
        ];
        return $map[ $errno ] ?? 'INFO';
    }
}
