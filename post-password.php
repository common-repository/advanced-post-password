<?php
/**
	* Plugin Name: Advanced Post Password
	* Plugin URI: https://garridodiaz.com/category/wp/
	* Description: Password protected posts/pages adding some extra security features.
	* Version: 1.1.2
	* Author: Chema 
	* Author URI: https://garridodiaz.com
	* Text Domain: advanced-post-password
	* License: GPL2
*/

if ( ! defined( 'ABSPATH' )) exit; // Exit if accessed directly


class Advanced_Post_Password{

	const MAIN_FILE = __FILE__;
	var $plugin_slug = 'advanced-post-password';

	public function __construct() 
	{
		// 1. action hook to create a new admin page and menu item, 2. array to run a method -> 1. $this (object), 2. unique name of the method
	    add_action('admin_menu', array($this, 'admin_page')); 

	    // 1. action hook to save data to db, 2. array to run a method -> 1. $this (object), 2. unique name of the method
	    add_action('admin_init', array($this, 'settings')); 

	    //locale
	    add_action('init', array($this, 'languages'));

	    add_filter('plugin_row_meta', [$this, 'addPluginRowMeta'], 10, 2);
	    add_filter('plugin_action_links_advanced-post-password/post-password.php',array($this,  'addSettingLinks'));
	    add_action('admin_notices', [$this, 'displayDonationMessage']);
        add_action('admin_head', [$this, 'addDonationMessageJS']);

	    //remove word from title
		if (get_option($this->plugin_slug.'-no-private-title'))
			add_filter('private_title_format', array($this, 'remove_protected_in_title'));

		if (get_option($this->plugin_slug.'-no-protected-title'))
			add_filter('protected_title_format', array($this, 'remove_protected_in_title'));

		// check password by cookie
		add_filter( 'post_password_required', array($this, 'cookie_post_password_required'), 10, 2 );
    	
		//intercept password submit to add extra cookies
    	$this->submit_post_password();
	}

	/**
	 * check if trying a post_password authentication so we can add extra cookie per page
	 */
	public function submit_post_password()
	{
		if ($_POST AND array_key_exists( 'post_password', $_POST ) ) 
		{
			//getting a referer if there's none we do nothing...
			$referer = strtok(wp_get_raw_referer(), '?');

			if ( $referer && wp_unslash( $_SERVER['REQUEST_URI'] ) !== $referer && home_url() . wp_unslash( $_SERVER['REQUEST_URI'] ) !== $referer ) 
			{
				//setting unique cookie name used later in cookie_post_password_required
				$cookie_name = 'wp-'.$this->plugin_slug.'_'.md5($referer).'_'. COOKIEHASH;

				//copied from wp-login.php case 'postpass':
				require_once ABSPATH . WPINC . '/class-phpass.php';
				$hasher = new PasswordHash( 8, true );

				$expire  = apply_filters( 'post_password_expires', time() + 365 * DAY_IN_SECONDS );

				if ( $referer ) {
					$secure = ( 'https' === parse_url( $referer, PHP_URL_SCHEME ) );
				} else {
					$secure = false;
				}

				setcookie( $cookie_name, $hasher->HashPassword( wp_unslash( $_POST['post_password'] ) ), $expire, COOKIEPATH, COOKIE_DOMAIN, $secure );


				//special page has access to all restricted pages
				//if correct password , cookie setup if they login in this special page
				if ( get_option($this->plugin_slug.'-master-url') == $referer AND get_option($this->plugin_slug.'-master-pwd') == $_POST['post_password'] )
				{
					setcookie( 'wp-'.$this->plugin_slug.'_all_' . COOKIEHASH, $hasher->HashPassword( get_option($this->plugin_slug.'-master-pwd') ), $expire, COOKIEPATH, COOKIE_DOMAIN, $secure );
				}

			}
		}
	}

	/**
	 * Whether post requires password and correct password has been provided. same as original but reading from different cookie
	 * @param  boolean $required 
	 * @param  id|post $post     
	 * @return boolean           
	 */
	public function cookie_post_password_required($required, $post)
	{
		$post = get_post( $post );

		if ( empty( $post->post_password ) ) 
			return false;

		//admin no need of password
		if (get_option($this->plugin_slug.'-no-admin-password') AND current_user_can( 'administrator' ) )
			return false;

		// if user had access to the special URL no need to request other pages passwords.
		if (get_option($this->plugin_slug.'-master-url')!=FALSE AND get_option($this->plugin_slug.'-master-pwd')!=FALSE) 
		{
			//he did access previously with a correct password to the special page
			if (!$this->check_cookie_pwd('wp-'.$this->plugin_slug.'_all_' . COOKIEHASH,get_option($this->plugin_slug.'-master-pwd')))
				return false;
		}

		//read correct cookie for this url/post
		$url = md5(get_permalink($post));
		$cookie_name = 'wp-'.$this->plugin_slug.'_'.$url.'_'. COOKIEHASH ;

		// check the password
		return $this->check_cookie_pwd($cookie_name, $post->post_password);
	}

	/**
	 * checks a password stored in a cookie
	 * @param  string $cookie_name comes with the cookiehash already
	 * @param  string $password    
	 * @return boolean false means correct password... I know it's confusing..... but its used in cookie_post_password_required
	 */
	private function check_cookie_pwd($cookie_name, $password)
	{
		if ( ! isset( $_COOKIE[ $cookie_name] ) ) {
			return true;
		}

		require_once ABSPATH . WPINC . '/class-phpass.php';
		$hasher = new PasswordHash( 8, true );

		$hash = wp_unslash( $_COOKIE[ $cookie_name] );
		if ( 0 !== strpos( $hash, '$P$B' ) ) {
			$required = true;
		} else {
			$required = ! $hasher->CheckPassword( $password, $hash );
		}

		return $required;
	}

  	/**
  	 * method to add an admin page and show it in the admin menu (Settings/)
  	 * @return void 
  	 */
	public function admin_page() 
	{
		add_options_page('Advanced Post Password', __('Post Password', 'advanced-post-password'), 'manage_options', $this->plugin_slug.'-settings-page', array($this, 'admin_HTML')); 
	}

	/**
	 * adding the settings for the plugin
	 * @return void
	 */
	public function settings() 
	{
	    // add section
	    add_settings_section($this->plugin_slug.'-first-section', null, null, $this->plugin_slug.'-settings-page'); 

	    // register admin no need password setting to be stored in the db & add field
	    add_settings_field($this->plugin_slug.'-no-admin-password', __('No admin password', 'advanced-post-password'), array($this, 'checkbox_HTML'),  $this->plugin_slug.'-settings-page', $this->plugin_slug.'-first-section', array('input_name' => $this->plugin_slug.'-no-admin-password')); 
	    register_setting($this->plugin_slug, $this->plugin_slug.'-no-admin-password', array('sanitize_callback' => 'absint', 'default' => '0'));

	    // register no protected title setting to be stored in the db & add field
	    add_settings_field($this->plugin_slug.'-no-protected-title', __('Removes protected prefix', 'advanced-post-password'), array($this, 'checkbox_HTML'),  $this->plugin_slug.'-settings-page', $this->plugin_slug.'-first-section', array('input_name' => $this->plugin_slug.'-no-protected-title')); 
	    register_setting($this->plugin_slug, $this->plugin_slug.'-no-protected-title', array('sanitize_callback' => 'absint', 'default' => '1'));

	    // register no protected title setting to be stored in the db & add field
	    add_settings_field($this->plugin_slug.'-no-private-title', __('Removes private prefix', 'advanced-post-password'), array($this, 'checkbox_HTML'),  $this->plugin_slug.'-settings-page', $this->plugin_slug.'-first-section', array('input_name' => $this->plugin_slug.'-no-private-title')); 
	    register_setting($this->plugin_slug, $this->plugin_slug.'-no-private-title', array('sanitize_callback' => 'absint', 'default' => '1'));

	    // add section
	    add_settings_section($this->plugin_slug.'-second-section', null, null, $this->plugin_slug.'-settings-page'); 

	    // register master url setting to be stored in the db & add field
	    add_settings_field($this->plugin_slug.'-master-url',  __('Master URL', 'advanced-post-password'), array($this, 'input_HTML'),  $this->plugin_slug.'-settings-page', $this->plugin_slug.'-second-section', array('input_name' => $this->plugin_slug.'-master-url')); 
	    register_setting($this->plugin_slug, $this->plugin_slug.'-master-url', array('sanitize_callback' => 'sanitize_text_field', 'default' => '/'));

	    // register master pwd setting to be stored in the db & add field
	    add_settings_field($this->plugin_slug.'-master-pwd',  __('Master URL password', 'advanced-post-password'), array($this, 'input_HTML'),  $this->plugin_slug.'-settings-page', $this->plugin_slug.'-second-section', array('input_name' => $this->plugin_slug.'-master-pwd')); 
	    register_setting($this->plugin_slug, $this->plugin_slug.'-master-pwd', array('sanitize_callback' => 'sanitize_text_field', 'default' => '/'));
 	}


 	function input_HTML($args) { ?>
	 	<input name="<?php echo esc_attr($args['input_name']) ?>" value="<?php echo esc_attr(get_option($args['input_name'])) ?>" > 
	 <?php }

	function checkbox_HTML($args) { ?>
		<input type="checkbox" name="<?php echo esc_attr($args['input_name']) ?>" value="1" <?php checked(get_option($args['input_name']), '1') ?>>
	<?php }


 	/**
 	 * method to write html in Settings
 	 * @return html
 	 */
	public function admin_HTML() 
	{ 
		require_once plugin_dir_path( __FILE__ ) . 'views/settings.php';
	}

	/**
	 * locale load
	 * @return void
	 */
	public function languages() 
	{
    	load_plugin_textdomain($this->plugin_slug, false, dirname(plugin_basename(__FILE__)) . '/languages');
  	}


  	/**
	 * Removes "Private" or "Protected" prefix that wordpress adds to password-protected & private pages thanks to https://wordpress.org/plugins/remove-protected-in-title/
	 * @param  string $title 
	 * @return string        
	 */
	public function remove_protected_in_title($title) 
	{
		return '%s';
	}

	/**
     * Add links to settings and sponsorship in plugin row meta.
     *
     * @param array $plugin_meta The existing plugin meta.
     * @param string $plugin_file The plugin file path.
     * @return array Modified plugin meta with added links.
     */
    public function addPluginRowMeta($plugin_meta, $plugin_file)
    {
        if (plugin_basename(self::MAIN_FILE) !== $plugin_file) {
            return $plugin_meta;
        }

        $settings_page_url = admin_url('options-general.php?page=advanced-post-password-settings-page');

        $plugin_meta[] = sprintf(
            '<a href="%1$s"><span class="dashicons dashicons-admin-settings" aria-hidden="true" style="font-size:14px;line-height:1.3"></span>%2$s</a>',
            $settings_page_url,
            esc_html_x('Settings', 'verb', 'advanced-post-password')
        );

        $plugin_meta[] = sprintf(
            '<a href="%1$s"><span class="dashicons dashicons-star-filled" aria-hidden="true" style="font-size:14px;line-height:1.3"></span>%2$s</a>',
            'https://paypal.me/chema/10EUR',
            esc_html_x('Sponsor', 'verb', 'advanced-post-password')
        );

        return $plugin_meta;
    }

    /**
     * add link to settings next to activate deactivate
     * @param [type] $links [description]
     */
    function addSettingLinks($links) 
	{
		$settings_page_url = admin_url('options-general.php?page=advanced-post-password-settings-page');

        $settings_link = sprintf(
            '<a href="%1$s">%2$s</a>',
            $settings_page_url,
            esc_html_x('Settings', 'verb', 'advanced-post-password')
        );

        array_unshift($links, $settings_link);
    	return $links;
	}


    /**
     * Display a donation message in the WordPress admin.
     */
    public function displayDonationMessage()
    {
        // Display the donation message
        if ((isset($_GET['page']) && $_GET['page'] === 'advanced-post-password-settings-page') && !isset($_COOKIE['app_donation_message_closed'])) {
            echo '<div id="donation-message" class="notice notice-info is-dismissible" style="background-color: #f5f5f5; border-left: 4px solid #0073aa; padding: 10px;">
                <p style="font-size: 16px;">';
            echo __('Enjoy using our plugin? Consider <a href="https://paypal.me/chema/10EUR" target="_blank" id="donate-link">making a donation</a> to support our work! THANKS!', 'advanced-post-password');
            echo '</p></div>';
        }
    }

    /**
     * Add JavaScript for handling the donation message.
     */
    public function addDonationMessageJS()
    {
        // Add JavaScript for handling the donation message
        if (!isset($_COOKIE['app_donation_message_closed'])) {
            ?>
            <script type="text/javascript">
                jQuery(document).ready(function ($) {

                    $('#donate-link').click(function () {
                        $('#donation-message').remove();
                        var expirationDate = new Date();
                        expirationDate.setDate(expirationDate.getDate() + 30); // Expires in 30 days
                        document.cookie = 'app_donation_message_closed=true; expires=' + expirationDate.toUTCString() + '; path=/';

                    });
                });
            </script>
            <?php
        }
    }
}


$Advanced_Post_Password = new Advanced_Post_Password();



?>
