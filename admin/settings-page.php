<?php
defined( 'ABSPATH' ) || exit;

class WPG_Settings_Page {

    private const PAGE_SLUG    = 'wp-guardian';
    private const OPTION_GROUP = 'wpg_options';

    public function __construct() {
        add_action( 'admin_menu',    [ $this, 'add_menu' ] );
        add_action( 'admin_init',    [ $this, 'register_settings' ] );
        add_action( 'admin_notices', [ $this, 'maybe_show_setup_notice' ] );
    }

    public function add_menu(): void {
        add_options_page(
            __( 'WP Guardian', 'wp-guardian' ),
            __( 'WP Guardian', 'wp-guardian' ),
            'manage_options',
            self::PAGE_SLUG,
            [ $this, 'render_page' ]
        );
    }

    public function register_settings(): void {
        register_setting( self::OPTION_GROUP, 'wpg_api_key',    [ 'sanitize_callback' => 'sanitize_text_field' ] );
        register_setting( self::OPTION_GROUP, 'wpg_server_url', [ 'sanitize_callback' => 'esc_url_raw' ] );
        register_setting( self::OPTION_GROUP, 'wpg_scan_enabled', [ 'sanitize_callback' => 'rest_sanitize_boolean', 'default' => true ] );
        register_setting( self::OPTION_GROUP, 'wpg_uptime_enabled', [ 'sanitize_callback' => 'rest_sanitize_boolean', 'default' => true ] );

        add_settings_section(
            'wpg_main_section',
            __( 'Connection Settings', 'wp-guardian' ),
            [ $this, 'render_section_info' ],
            self::PAGE_SLUG
        );

        add_settings_field( 'wpg_server_url', __( 'Server URL', 'wp-guardian' ), [ $this, 'render_server_url' ], self::PAGE_SLUG, 'wpg_main_section' );
        add_settings_field( 'wpg_api_key',    __( 'API Key', 'wp-guardian' ),    [ $this, 'render_api_key' ],    self::PAGE_SLUG, 'wpg_main_section' );

        add_settings_section( 'wpg_features_section', __( 'Features', 'wp-guardian' ), '__return_false', self::PAGE_SLUG );
        add_settings_field( 'wpg_scan_enabled',   __( 'Security scanning', 'wp-guardian' ), [ $this, 'render_scan_toggle' ],   self::PAGE_SLUG, 'wpg_features_section' );
        add_settings_field( 'wpg_uptime_enabled', __( 'Uptime monitoring', 'wp-guardian' ), [ $this, 'render_uptime_toggle' ], self::PAGE_SLUG, 'wpg_features_section' );
    }

    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;
        $status = $this->test_connection();
        ?>
        <div class="wrap">
            <h1>
                <span dashicons="shield" style="color:#4f6ef7;font-size:28px;vertical-align:middle;">🛡</span>
                <?php esc_html_e( 'WP Guardian', 'wp-guardian' ); ?>
                <span style="font-size:13px;font-weight:normal;color:#666;margin-left:8px;">v<?php echo esc_html( WPG_VERSION ); ?></span>
            </h1>

            <?php if ( $status !== null ): ?>
                <div class="notice notice-<?php echo $status ? 'success' : 'error'; ?> is-dismissible">
                    <p><?php echo $status ? esc_html__( '✓ Connected to WP Guardian server.', 'wp-guardian' ) : esc_html__( '✗ Could not reach WP Guardian server. Check your URL and API key.', 'wp-guardian' ); ?></p>
                </div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php
                settings_fields( self::OPTION_GROUP );
                do_settings_sections( self::PAGE_SLUG );
                submit_button( __( 'Save Settings', 'wp-guardian' ) );
                ?>
            </form>

            <hr>
            <h2><?php esc_html_e( 'Manual Actions', 'wp-guardian' ); ?></h2>
            <p>
                <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-guardian&wpg_action=test' ) ); ?>" class="button button-secondary">
                    <?php esc_html_e( 'Test Connection', 'wp-guardian' ); ?>
                </a>
                &nbsp;
                <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-guardian&wpg_action=scan' ) ); ?>" class="button button-secondary">
                    <?php esc_html_e( 'Run Security Scan Now', 'wp-guardian' ); ?>
                </a>
                &nbsp;
                <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-guardian&wpg_action=flush' ) ); ?>" class="button button-secondary">
                    <?php esc_html_e( 'Flush Log Buffer Now', 'wp-guardian' ); ?>
                </a>
            </p>
        </div>
        <?php
    }

    public function render_section_info(): void {
        echo '<p>' . esc_html__( 'Enter the URL of your WP Guardian server and the API key shown in the dashboard for this site.', 'wp-guardian' ) . '</p>';
    }

    public function render_server_url(): void {
        $val = get_option( 'wpg_server_url', '' );
        echo '<input type="url" name="wpg_server_url" value="' . esc_attr( $val ) . '" class="regular-text" placeholder="https://your-server.example.com" />';
    }

    public function render_api_key(): void {
        $val = get_option( 'wpg_api_key', '' );
        echo '<input type="text" name="wpg_api_key" value="' . esc_attr( $val ) . '" class="regular-text" placeholder="wpg_..." />';
        echo '<p class="description">' . esc_html__( 'Find this in WP Guardian → Sites → your site → API Key.', 'wp-guardian' ) . '</p>';
    }

    public function render_scan_toggle(): void {
        $val = get_option( 'wpg_scan_enabled', true );
        echo '<label><input type="checkbox" name="wpg_scan_enabled" value="1" ' . checked( $val, true, false ) . ' /> ' . esc_html__( 'Enable automatic security scans (twice daily)', 'wp-guardian' ) . '</label>';
    }

    public function render_uptime_toggle(): void {
        $val = get_option( 'wpg_uptime_enabled', true );
        echo '<label><input type="checkbox" name="wpg_uptime_enabled" value="1" ' . checked( $val, true, false ) . ' /> ' . esc_html__( 'Enable uptime heartbeat (every 5 minutes)', 'wp-guardian' ) . '</label>';
    }

    public function maybe_show_setup_notice(): void {
        $screen = get_current_screen();
        if ( $screen && str_contains( $screen->id, self::PAGE_SLUG ) ) return;

        if ( empty( get_option( 'wpg_api_key' ) ) || empty( get_option( 'wpg_server_url' ) ) ) {
            echo '<div class="notice notice-warning"><p>';
            printf(
                wp_kses(
                    __( '<strong>WP Guardian</strong> is not configured. <a href="%s">Configure it now</a>.', 'wp-guardian' ),
                    [ 'strong' => [], 'a' => [ 'href' => [] ] ]
                ),
                esc_url( admin_url( 'options-general.php?page=wp-guardian' ) )
            );
            echo '</p></div>';
        }

        // Handle manual action buttons
        if ( isset( $_GET['wpg_action'] ) && current_user_can( 'manage_options' ) ) {
            switch ( $_GET['wpg_action'] ) {
                case 'scan':
                    do_action( 'wpg_security_scan' );
                    echo '<div class="notice notice-success"><p>' . esc_html__( 'Security scan completed.', 'wp-guardian' ) . '</p></div>';
                    break;
                case 'flush':
                    do_action( 'wpg_flush_logs' );
                    echo '<div class="notice notice-success"><p>' . esc_html__( 'Log buffer flushed.', 'wp-guardian' ) . '</p></div>';
                    break;
            }
        }
    }

    private function test_connection(): ?bool {
        if ( ! isset( $_GET['wpg_action'] ) || $_GET['wpg_action'] !== 'test' ) {
            return null;
        }

        $api_key    = get_option( 'wpg_api_key', '' );
        $server_url = get_option( 'wpg_server_url', '' );
        if ( empty( $api_key ) || empty( $server_url ) ) return false;

        $client = new WPG_API_Client( $server_url, $api_key );
        return $client->ingest( [ 'logs' => [] ] );
    }
}
