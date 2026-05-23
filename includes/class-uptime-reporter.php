<?php
defined( 'ABSPATH' ) || exit;

/**
 * Sends uptime heartbeat pings and performance metrics every 5 minutes.
 */
class WPG_Uptime_Reporter {

    private WPG_API_Client $client;

    public function __construct( WPG_API_Client $client ) {
        $this->client = $client;
        add_action( 'wpg_uptime_ping', [ $this, 'send_ping' ] );

        // Also capture page load time on each request (frontend only)
        if ( ! is_admin() ) {
            add_action( 'wp_footer', [ $this, 'capture_page_load' ] );
        }
    }

    /**
     * Ping the site's home URL and report uptime + response time.
     */
    public function send_ping(): void {
        $start    = microtime( true );
        $response = wp_remote_get( home_url( '/' ), [
            'timeout'    => 10,
            'user-agent' => 'WPGuardian-UptimeBot/1.0',
            'sslverify'  => false,
        ] );
        $elapsed_ms = (int) round( ( microtime( true ) - $start ) * 1000 );

        if ( is_wp_error( $response ) ) {
            $payload = [
                'status'         => 'down',
                'error_message'  => $response->get_error_message(),
                'response_time_ms' => $elapsed_ms,
            ];
        } else {
            $code    = (int) wp_remote_retrieve_response_code( $response );
            $status  = $this->code_to_status( $code, $elapsed_ms );
            $payload = [
                'status'            => $status,
                'http_status_code'  => $code,
                'response_time_ms'  => $elapsed_ms,
            ];
        }

        $this->client->ingest( [
            'uptime'  => $payload,
            'metrics' => $this->collect_server_metrics(),
        ] );
    }

    /**
     * Capture page load timing from PHP perspective (injected via footer hook).
     * Real User Monitoring (RUM) would need JS — this is server-side only.
     */
    public function capture_page_load(): void {
        // $_SERVER['REQUEST_TIME_FLOAT'] is set by PHP at request start
        if ( isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ) {
            $duration_ms = (int) round( ( microtime( true ) - $_SERVER['REQUEST_TIME_FLOAT'] ) * 1000 );
            $this->client->ingest( [
                'metrics' => [ [
                    'metric_type' => 'page_load_ms',
                    'value'       => (float) $duration_ms,
                    'unit'        => 'ms',
                    'metadata'    => [
                        'url'    => $_SERVER['REQUEST_URI'] ?? '/',
                        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
                    ],
                ] ],
            ] );
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function code_to_status( int $code, int $ms ): string {
        if ( $code >= 500 )       return 'down';
        if ( $code >= 400 )       return 'degraded';
        if ( $ms > 5000 )         return 'degraded';
        return 'up';
    }

    private function collect_server_metrics(): array {
        $metrics = [];

        // Memory usage
        $mem = memory_get_usage( true );
        $metrics[] = [
            'metric_type' => 'memory_usage',
            'value'       => round( $mem / 1024 / 1024, 2 ),
            'unit'        => 'MB',
        ];

        // Peak memory
        $peak = memory_get_peak_usage( true );
        $metrics[] = [
            'metric_type' => 'memory_peak',
            'value'       => round( $peak / 1024 / 1024, 2 ),
            'unit'        => 'MB',
        ];

        // Memory limit
        $limit_str = ini_get( 'memory_limit' );
        $metrics[] = [
            'metric_type' => 'memory_limit',
            'value'       => (float) $this->parse_bytes( $limit_str ) / 1024 / 1024,
            'unit'        => 'MB',
        ];

        // DB query count (WordPress global)
        global $wpdb;
        if ( isset( $wpdb->num_queries ) ) {
            $metrics[] = [
                'metric_type' => 'db_query_count',
                'value'       => (float) $wpdb->num_queries,
                'unit'        => 'count',
            ];
        }

        // Max execution time
        $max_exec = (int) ini_get( 'max_execution_time' );
        if ( $max_exec > 0 ) {
            $metrics[] = [
                'metric_type' => 'max_execution_time',
                'value'       => (float) $max_exec,
                'unit'        => 'seconds',
            ];
        }

        return $metrics;
    }

    private function parse_bytes( string $val ): int {
        $val  = trim( $val );
        $last = strtolower( $val[ strlen( $val ) - 1 ] );
        $num  = (int) $val;
        switch ( $last ) {
            case 'g': $num *= 1024;
            case 'm': $num *= 1024;
            case 'k': $num *= 1024;
        }
        return $num;
    }
}
