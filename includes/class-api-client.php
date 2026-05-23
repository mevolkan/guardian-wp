<?php
defined( 'ABSPATH' ) || exit;

/**
 * Handles all HTTP communication with the WP Guardian server.
 */
class WPG_API_Client {

    private string $server_url;
    private string $api_key;
    private int    $timeout = 15;

    public function __construct( string $server_url, string $api_key ) {
        $this->server_url = trailingslashit( $server_url );
        $this->api_key    = $api_key;
    }

    /**
     * Send an ingest payload to the server.
     *
     * @param array $payload  Associative array matching the IngestPayload schema.
     * @return bool           True on success, false on failure.
     */
    public function ingest( array $payload ): bool {
        $url      = $this->server_url . 'api/v1/ingest/';
        $body     = wp_json_encode( $payload );
        $response = wp_remote_post( $url, [
            'timeout'     => $this->timeout,
            'headers'     => [
                'Content-Type' => 'application/json',
                'X-API-Key'    => $this->api_key,
            ],
            'body'        => $body,
            'data_format' => 'body',
        ] );

        if ( is_wp_error( $response ) ) {
            error_log( '[WP Guardian] Ingest error: ' . $response->get_error_message() );
            return false;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code < 200 || $code >= 300 ) {
            error_log( '[WP Guardian] Ingest HTTP ' . $code . ': ' . wp_remote_retrieve_body( $response ) );
            return false;
        }

        return true;
    }
}
