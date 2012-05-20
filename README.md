Opauth-Twitter
=============
Twitter strategy for [Opauth][1], based on Opauth-OAuth.

Getting started
----------------
1. Install Opauth-Twitter:
   ```bash
   cd path_to_opauth/Strategy
   git clone git://github.com/uzyn/opauth-twitter.git Twitter
   ```

2. Create Twitter application at https://dev.twitter.com/apps
   - Make sure to enter a Callback URL or callback will be disallowed.  
      Callback URL can be a made up one as Opauth will explicitly provide the correct one as part of the OAuth process.   
   - Register your domains at @Anywhere domains.  
	   Twitter only allows authentication from authorized domains.
	
3. Configure Opauth-Facebook strategy with at least `Consumer key` and `Consumer secret`.

4. Direct user to `http://path_to_opauth/twitter` to authenticate


Strategy configuration
----------------------

Required parameters:

```php
<?php
'Twitter' => array(
	'key' => 'YOUR CONSUMER KEY',
	'secret' => 'YOUR CONSUMER SECRET'
)
```

See Twitter.php for optional parameters.

Opauth-Twitter does "[Sign In with Twitter](https://dev.twitter.com/docs/auth/implementing-sign-twitter)" by default.  
If you prefer to do a [3-legged OAuth](https://dev.twitter.com/docs/auth/3-legged-authorization), explicitly add `authenticate_url` parameter to strategy configuration and set it to `https://api.twitter.com/oauth/authorize`.

Dependencies
------------
tmhOAuth requires hash_hmac and cURL.  
hash_hmac is available on PHP 5 >= 5.1.2.

Reference
---------
 - [Twitter Authentication & Authorization](https://dev.twitter.com/docs/auth)

License
---------
Opauth-Twitter is MIT Licensed  
Copyright © 2012 U-Zyn Chua (http://uzyn.com)

tmhOAuth is [Apache 2 licensed](https://github.com/themattharris/tmhOAuth/blob/master/LICENSE).

[1]: https://github.com/uzyn/opauth