<?php
/**
	* Plugin Name: Advanced Post Password
	* Plugin URI: https://garridodiaz.com
	* Description: Password protected posts/pages adding some extra security features.
	* Version: 1.1.2
	* Author: Chema 
	* Author URI: https://garridodiaz.com
	* License: GPL2
*/

if ( ! defined( 'ABSPATH' )) exit; // Exit if accessed directly

?>

<div class="wrap">
  <h1><?php echo __('Advanced Post Password', 'advanced-post-password');?></h1>
  <form action="options.php" method="POST">
  <?php
    settings_fields($this->plugin_slug);
    do_settings_sections($this->plugin_slug.'-settings-page');
    submit_button();
  ?>
  </form>
</div>

<?php
?>