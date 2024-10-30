<?php
/*
Plugin Name: Login via exchange
Plugin URI: https://wordpress.org/plugins/login-via-exchange/
Description:  Authenticate WordPress against exchange web service.
Version: 1.0.0
Author: Daif Alotaibi.
Author URI: http://daif.net
*/

// Prohibit direct script loading.
defined( 'ABSPATH' ) || die( 'No direct script access allowed!' );

// define plug-in constants
define( 'LOGINVIAEXCHANGE_VERSION',    '1.0.0' );
define( 'LOGINVIAEXCHANGE_FILE',       __FILE__ );
define( 'LOGINVIAEXCHANGE_PATH',       dirname(LOGINVIAEXCHANGE_FILE) );

class loginviaexchange {
    static $instance = null;
    public function __construct () {
        // register activation hook
        register_activation_hook( __FILE__,     [get_called_class(), 'activation_hook']);
        // register deactivation hook
        register_deactivation_hook( __FILE__,   [get_called_class(), 'deactivate_hook']);
        // add authenticate filter
        add_filter('authenticate', array($this, 'authenticate_filter'), 11, 3);
        // add admin menu action
        add_action( 'admin_menu',               [get_called_class(), 'admin_menu_action'] );
    }
    public static function getInstance () {
        if ( !self::$instance ) {
          self::$instance = new self;
        }
        return self::$instance;
    }
    function activation_hook () {
        // set default options
        if(get_option('loginviaexchange_ews_url')          == '')  add_option('loginviaexchange_ews_url'          ,'https://mail.domain.ltd/EWS/exchange.asmx');
        if(get_option('loginviaexchange_allow_wp_user')    == '')  add_option('loginviaexchange_allow_wp_user'    ,'true');
        // plugin info
        if(get_option('loginviaexchange_version')          == '')  add_option('loginviaexchange_version'          ,LOGINVIAEXCHANGE_VERSION);
    }
    function deactivate_hook () {
        //delete options
        delete_option('loginviaexchange_ews_url');
        delete_option('loginviaexchange_allow_wp_user');
        delete_option('loginviaexchange_version');
    }
    function admin_menu_action () {
        add_menu_page('Login via exchange settings', 'Login via exchange', 'manage_options', 'login-via-exchange', [ get_called_class(), 'admin_menu_page'] , 'dashicons-groups');
    }
    function admin_menu_page () {
        if($_SERVER['REQUEST_METHOD'] == 'POST') {
            // filtering inputs
            $loginviaexchange_ews_url          = parse_url($_POST['loginviaexchange_ews_url']);
            $loginviaexchange_allow_wp_user    = filter_var($_POST['loginviaexchange_allow_wp_user'],     FILTER_VALIDATE_BOOLEAN);
            // make sure input are valid 
            if(isset($loginviaexchange_ews_url['scheme']) && isset($loginviaexchange_ews_url['host']) && isset($loginviaexchange_ews_url['path'])) {
                update_option('loginviaexchange_ews_url',      $loginviaexchange_ews_url['scheme'].'://'.$loginviaexchange_ews_url['host'].$loginviaexchange_ews_url['path']);
            }
            if($loginviaexchange_allow_wp_user == 'true' || $loginviaexchange_allow_wp_user == 'false') {
                update_option('loginviaexchange_allow_wp_user',    $loginviaexchange_allow_wp_user);
            }
        }

        $page   = [];
        $page[] = '<div class="wrap">';
        $page[] = '<h1>'.esc_html( get_admin_page_title() ).'</h1>';
        $page[] = '<form method="post" action="'.admin_url( 'admin.php?page=login-via-exchange' ).'">';

        $page[] = '<table class="form-table">';
        $page[] = '<tr>';
            $page[] = '<th scope="row"><label for="loginviaexchange_ews_url">'.__('Exchange EWS URL').'</label></th>';
            $page[] = '<td>';
            $page[] = '<input name="loginviaexchange_ews_url" type="text" id="loginviaexchange_ews_url" value="'.get_option('loginviaexchange_ews_url').'" class="regular-text" />';
            $page[] = '<p class="description">The full URL to exchange web service, ex: https://mail.domain.ltd/EWS/exchange.asmx</p>';
            $page[] = '</td>';
        $page[] = '</tr>';

        $page[] = '<tr>';
            $page[] = '<th scope="row"><label for="loginviaexchange_allow_wp_user">'.__('Allow local users').'</label></th>';
            $page[] = '<td>';
            $page[] = '<select name="loginviaexchange_allow_wp_user" id="loginviaexchange_allow_wp_user">';
            $page[] = '<option value="true" '.((get_option('loginviaexchange_allow_wp_user') == true)?'selected="selected"':'').'>Allowed</option>';
            $page[] = '<option value="false" '.((get_option('loginviaexchange_allow_wp_user') == false)?'selected="selected"':'').'>Not allowed</option>';
            $page[] = '</select>';
            $page[] = '<p class="description">Allow wordpress local users to login</p>';
            $page[] = '</td>';
        $page[] = '</tr>';

        $page[] = '</table>';
        $page[] = '<p class="description">Please test your setting before saving.</p>';
        $page[] = get_submit_button();
        $page[] = '</form>';
        $page[] = '</div>';

        print implode("\n", $page);
    }

    function authenticate_filter ($user, $username, $password) {
        // if user already logged in
        if ( $user instanceof WP_User ) {
            return $user;
        }
        // if request is not POST ignore it
        if($_SERVER['REQUEST_METHOD'] != 'POST') {
            return;
        }
        // if local user is not allowed remove 
        if(get_option('loginviaexchange_allow_wp_user') != true) {
            remove_action('authenticate', 'wp_authenticate_username_password', 20);
            remove_action('authenticate', 'wp_authenticate_email_password', 20); 
        }
        // get exchange login options
        $ews_url        = get_option('loginviaexchange_ews_url');
        $allow_wp_user  = get_option('loginviaexchange_allow_wp_user');

        $ews_domain  = parse_url($ews_url, PHP_URL_HOST);
        $ews_domain  = str_ireplace(array('mail.','www.'), '', $ews_domain);
        $user_domain = '';
        if(strpos($username, '@')) {
            list($username, $user_domain) = explode('@', $username, 2);
        }
        if(strtolower($user_domain) == strtolower($ews_domain)) {
            $code       = 'invalid_username';
            $message    = __('<strong>Exchange Login Error</strong>: in-correct user email domain.');
            return new WP_Error( $code, $message );
        }
        // connect to exchange web service and try to login using username and password
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $ews_url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
        curl_setopt($ch, CURLOPT_USERPWD, $username.':'.$password);
        $data = curl_exec($ch);
        if(!$data || curl_getinfo($ch, CURLINFO_HTTP_CODE) != '200') {
            $code       = 'invalid_username';
            $message    = __('<strong>Exchange Login Error</strong>: wrong username or password.');
            return new WP_Error( $code, $message );
        }
        // make userdata array 
        $userdata = [
            'user_login'    =>  $username,
            'user_pass'     =>  $password,
            'user_nicename' =>  $username,
            'user_email'    =>  $username,
            'display_name'  =>  $username,
        ];
        // check if user already existed 
        $user_id = username_exists($username);
        if ( $user_id ) {
            $userdata['ID'] = $user_id;
            wp_update_user($userdata);
        } else {
            $user_id = wp_insert_user( $userdata );
        }
        // check if user is already existed 
        $user_id = username_exists($username);
        $user    = get_user_by( 'ID', $user_id );
        if ( $user instanceof WP_User ) {
            return $user;
        }
        // return generic error of failure 
        $code       = 'invalid_username';
        $message    = __('<strong>Exchange Login Error</strong>: invalid username or password.');
        return new WP_Error( $code, $message );
    }
}

//create Instance
$loginviaexchange = loginviaexchange::getInstance();
