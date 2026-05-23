<?php
/**
 * Plugin Name: WP Guardian
 * Plugin URI:  https://wpguardian.io
 * Description: Sends WordPress logs, vulnerability scans, uptime heartbeats and performance metrics to the WP Guardian SaaS platform for centralised analysis.
 * Version:     1.0.0
 * Author:      WP Guardian
 * License:     GPL-2.0-or-later
 * Text Domain: wp-guardian
 */

defined( 'ABSPATH' ) || exit;

define( 'WPG_VERSION',    '1.0.0' );
define( 'WPG_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPG_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// ── Autoload includes ─────────────────────────────────────────────────────────
require_once WPG_PLUGIN_DIR . 'includes/class-api-client.php';
require_once WPG_PLUGIN_DIR . 'includes/class-log-collector.php';
require_once WPG_PLUGIN_DIR . 'includes/class-security-scanner.php';
require_once WPG_PLUGIN_DIR . 'includes/class-uptime-reporter.php';

// ── Bootstrap ─────────────────────────────────────────────────────────────────
add_action( 'plugins_loaded', [ 'WPG_Plugin', 'init' ] );

class WPG_Plugin {

    private static $instance = null;

    public static function init() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Admin settings page
        if ( is_admin() ) {
            require_once WPG_PLUGIN_DIR . 'admin/settings-page.php';
            new WPG_Settings_Page();
        }

        $api_key    = get_option( 'wpg_api_key', '' );
        $server_url = get_option( 'wpg_server_url', '' );

        if ( empty( $api_key ) || empty( $server_url ) ) {
            return; // Not configured yet
        }

        $client = new WPG_API_Client( $server_url, $api_key );

        // Start collectors
        new WPG_Log_Collector( $client );
        new WPG_Security_Scanner( $client );
        new WPG_Uptime_Reporter( $client );
    }

    // ── Activation / deactivation ─────────────────────────────────────────────
    public static function activate() {
        // Schedule cron jobs if not already scheduled
        if ( ! wp_next_scheduled( 'wpg_security_scan' ) ) {
            wp_schedule_event( time(), 'twicedaily', 'wpg_security_scan' );
        }
        if ( ! wp_next_scheduled( 'wpg_uptime_ping' ) ) {
            wp_schedule_event( time(), 'wpg_every_5_min', 'wpg_uptime_ping' );
        }
        if ( ! wp_next_scheduled( 'wpg_flush_logs' ) ) {
            wp_schedule_event( time(), 'hourly', 'wpg_flush_logs' );
        }
    }

    public static function deactivate() {
        foreach ( [ 'wpg_security_scan', 'wpg_uptime_ping', 'wpg_flush_logs' ] as $hook ) {
            $timestamp = wp_next_scheduled( $hook );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, $hook );
            }
        }
    }
}

register_activation_hook(   __FILE__, [ 'WPG_Plugin', 'activate' ] );
register_deactivation_hook( __FILE__, [ 'WPG_Plugin', 'deactivate' ] );

// ── Custom cron interval (every 5 minutes) ────────────────────────────────────
add_filter( 'cron_schedules', function ( $schedules ) {
    $schedules['wpg_every_5_min'] = [
        'interval' => 300,
        'display'  => __( 'Every 5 minutes', 'wp-guardian' ),
    ];
    return $schedules;
} );
