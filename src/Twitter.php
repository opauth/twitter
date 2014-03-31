<?php
/**
 * Twitter strategy for Opauth
 * Based on https://dev.twitter.com/docs/auth/obtaining-access-tokens
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.TwitterStrategy
 * @license      MIT License
 */
namespace Opauth\Twitter\Strategy;

use Opauth\Opauth\AbstractStrategy;
use Opauth\Opauth\TransportInterface;

class Twitter extends AbstractStrategy
{

    /**
     * Compulsory parameters
     */
    public $expects = array('key', 'secret');

    /**
     * Optional parameters
     */
    public $defaults = array(
        // For Twitter
        'request_token_url' => 'https://api.twitter.com/oauth/request_token',
        'authorize_url' => 'https://api.twitter.com/oauth/authenticate', // or 'https://api.twitter.com/oauth/authorize'
        'access_token_url' => 'https://api.twitter.com/oauth/access_token',
        'verify_credentials_json_url' => 'https://api.twitter.com/1.1/account/verify_credentials.json',
        'verify_credentials_skip_status' => true,
        'twitter_profile_url' => 'http://twitter.com/',
        // From tmhOAuth
        'user_token' => '',
        'user_secret' => '',
        'use_ssl' => true,
        'debug' => false,
        'force_nonce' => false,
        'nonce' => false, // used for checking signatures. leave as false for auto
        'force_timestamp' => false,
        'timestamp' => false, // used for checking signatures. leave as false for auto
        'oauth_version' => '1.0',
        'curl_connecttimeout' => 30,
        'curl_timeout' => 10,
        'curl_ssl_verifypeer' => false,
        'curl_followlocation' => false, // whether to follow redirects or not
        'curl_proxy' => false, // really you don't want to use this if you are using streaming
        'curl_proxyuserpwd' => false, // format username:password for proxy, if required
        'is_streaming' => false,
        'streaming_eol' => "\r\n",
        'streaming_metrics_interval' => 60,
        'as_header' => true,
    );

    protected $responseMap = array(
        'uid' => 'id',
        'name' => 'name',
        'info.name' => 'name',
        'info.nickname' => 'screen_name',
        'info.location' => 'location',
        'info.description' => 'description',
        'info.image' => 'profile_image_url',
        'info.urls.website' => 'url'
    );

    public function __construct($config, $callbackUrl, TransportInterface $transport)
    {
        parent::__construct($config, $callbackUrl, $transport);

        $this->strategy['consumer_key'] = $this->strategy['key'];
        $this->strategy['consumer_secret'] = $this->strategy['secret'];
        $this->tmhOAuth = new \tmhOAuth($this->strategy);
    }

    /**
     * Auth request
     */
    public function request()
    {
        $params = array(
            'oauth_callback' => $this->callbackUrl()
        );
        $results = $this->tmhRequest('POST', $this->strategy['request_token_url'], $params);

        if ($results === false || empty($results['oauth_token']) || empty($results['oauth_token_secret'])) {
            return $this->requestError();
        }
        $this->sessionData($results);

        $this->authorize($results['oauth_token']);
    }

    /**
     * Receives oauth_verifier, requests for access_token
     */
    public function callback()
    {
        $results = $this->verifier();
        if ($results === false || empty($results['oauth_token']) || empty($results['oauth_token_secret'])) {
            return $this->verifierError();
        }

        $credentials = $this->verifyCredentials($results['oauth_token'], $results['oauth_token_secret']);

        if ($credentials === false || empty($credentials['id'])) {
            return $this->credentialsError();
        }

        $response = $this->response($credentials);
        $response->credentials = array(
            'token' => $results['oauth_token'],
            'secret' => $results['oauth_token_secret']
        );
        $response->info['urls']['twitter'] = $this->strategy['twitter_profile_url'] . $credentials['screen_name'];
        $response->setMap($this->responseMap);
        return $response;
    }

    protected function verifier()
    {
        $session = $this->sessionData();
        if (empty($_REQUEST['oauth_token']) || $_REQUEST['oauth_token'] != $session['oauth_token']) {
            return $this->deniedError();
        }

        $this->tmhOAuth->config['user_token'] = $session['oauth_token'];
        $this->tmhOAuth->config['user_secret'] = $session['oauth_token_secret'];
        $params = array(
            'oauth_verifier' => $_REQUEST['oauth_verifier']
        );

        return $this->tmhRequest('POST', $this->strategy['access_token_url'], $params);
    }

    protected function authorize($oauth_token)
    {
        $params = array(
            'oauth_token' => $oauth_token
        );
        $params = $this->addParams(array('force_login', 'screen_name'), $params);
        $this->http->redirect($this->strategy['authorize_url'], $params);
    }

    protected function verifyCredentials($user_token, $user_token_secret)
    {
        $this->tmhOAuth->config['user_token'] = $user_token;
        $this->tmhOAuth->config['user_secret'] = $user_token_secret;

        $params = $this->addParams(array('verify_credentials_skip_status' => 'skip_status'));

        $response = $this->tmhRequest('GET', $this->strategy['verify_credentials_json_url'], $params);
        if ($response === false) {
            return false;
        }

        return $this->recursiveGetObjectVars($response);
    }


    /**
     * Wrapper of tmhOAuth's request() with Opauth's error handling.
     *
     * request():
     * Make an HTTP request using this library. This method doesn't return anything.
     * Instead the response should be inspected directly.
     *
     * @param string $method the HTTP method being used. e.g. POST, GET, HEAD etc
     * @param string $url the request URL without query string parameters
     * @param array $params the request parameters as an array of key=value pairs
     * @param string $useauth whether to use authentication when making the request. Default true.
     * @param string $multipart whether this request contains multipart data. Default false
     */
    protected function tmhRequest($method, $url, $params = array(), $useauth = true, $multipart = false)
    {
        $code = $this->tmhOAuth->request($method, $url, $params, $useauth, $multipart);

        if ($code !== 200) {
            return false;
        }

        if (strpos($url, '.json') !== false) {
            return json_decode($this->tmhOAuth->response['response']);
        }
        return $this->tmhOAuth->extract_params($this->tmhOAuth->response['response']);
    }

    protected function requestError()
    {
        return $this->error(
            'Could not obtain token from request_token_url.',
            'token_request_failed',
            $this->tmhOAuth->response
        );
    }

    protected function deniedError()
    {
        return $this->error(
            'User denied access.',
            'access_denied',
            $_GET
        );
    }

    protected function verifierError()
    {
        return $this->error(
            'OAuth verifier error.',
            'oauth_verifier_error',
            $this->tmhOAuth->response
        );
    }

    protected function credentialsError()
    {
        return $this->error(
            'Failed when verifying credentials.',
            'verify_credentials_error',
            $this->tmhOAuth->response
        );
    }
}
