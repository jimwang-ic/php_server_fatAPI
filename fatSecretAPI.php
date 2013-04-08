<?php

// Include Composer-generated autoloader
require(__DIR__.'/vendor/autoload.php');

define('API_URL', 'http://platform.fatsecret.com/js?');

//please register at http://platform.fatsecret.com for an API KEY 
define('API_KEY', '1d1e36bf07f84761b76cd39e0ad1c1dd');

//please register at http://platform.fatsecret.com for an API SECRET
define('API_SECRET', '809d548a-d738-45aa-9c41-f31e7506be01'); 


class FatSecretAPI{
	static public $base = 'http://platform.fatsecret.com/rest/server.api?';
	
	/* Private Data */
	private $_consumerKey;
	private $_consumerSecret;
	
	/* Constructors */	
    function FatSecretAPI($consumerKey, $consumerSecret){
		$this->_consumerKey = $consumerKey;
		$this->_consumerSecret = $consumerSecret;
		return $this;
	}
	
	/* Properties */
	function GetKey(){
		return $this->_consumerKey;
	}
	
	function SetKey($consumerKey){
		$this->_consumerKey = $consumerKey;
	}

	function GetSecret(){
		return $this->_consumerSecret;
	}
	
	function SetSecret($consumerSecret){
		$this->_consumerSecret = $consumerSecret;
	}
	
	/* Search Food
	* @param search {string} query string for searching food
	*/
	
	// public method are made available to the network
	public function foodSearch($search,$callback){
		
		$user_id = null;
		$token = null;
		$secret = null;
		
		$url = FatSecretAPI::$base.'method=foods.search';  
		if (!empty($user_id)) $url .= '&user_id='.$user_id;
		$url .= '&search_expression='.$search;
		$url .= '&generic_description=portion';
		$url .= '&max_results=10';
		
		$oauth = new OAuthBase();
	
		$normalizedUrl;
		$normalizedRequestParameters;
		
		$signature = $oauth->GenerateSignature($url, $this->_consumerKey, $this->_consumerSecret, $token, $secret, $normalizedUrl, $normalizedRequestParameters);
		$normalizedRequestParameters .= '&' . OAuthBase::$OAUTH_SIGNATURE . '=' . urlencode($signature);
		
		$queryResponse = $this->GetQueryResponse($normalizedUrl,$normalizedRequestParameters);
		
		$doc = new SimpleXMLElement($queryResponse);       	        
		
		$this->ErrorCheck($doc);
		
		$json = json_encode($doc);
		
		$callback($json);
		
	}  
	
	/* Get Food
	* @param food_id {string} the unique food identifier
	*/
	
	// public method are made available to the network
	public function getFood($food_id,$callback){
		
		$user_id = null;
		$token = null;
		$secret = null;
		
		$url = FatSecretAPI::$base.'method=food.get&food_id='.$food_id;  
		if (!empty($user_id)) $url .= '&user_id='.$user_id;
		
		$oauth = new OAuthBase();
	
		$normalizedUrl;
		$normalizedRequestParameters;
		
		$signature = $oauth->GenerateSignature($url, $this->_consumerKey, $this->_consumerSecret, $token, $secret, $normalizedUrl, $normalizedRequestParameters);
		$normalizedRequestParameters .= '&' . OAuthBase::$OAUTH_SIGNATURE . '=' . urlencode($signature);
		
		$queryResponse = $this->GetQueryResponse($normalizedUrl,$normalizedRequestParameters);
		
		$doc = new SimpleXMLElement($queryResponse);        	        
		
		$this->ErrorCheck($doc);
		
		$json = json_encode($doc);
		
		$callback($json);
	}
	
	/* Search recipe
	* @param search {string} query string for searching recipe
	*/
	
	// public method are made available to the network
	public function recipeSearch($search,$callback){
	
		$user_id = null;
		$token = null;
		$secret = null;
		
		$url = FatSecretAPI::$base.'method=recipes.search';  
		if (!empty($user_id)) $url .= '&user_id='.$user_id;
		$url .= '&search_expression='.$search;
	    
		$oauth = new OAuthBase();
	
		$normalizedUrl;
		$normalizedRequestParameters;
		
		$signature = $oauth->GenerateSignature($url, $this->_consumerKey, $this->_consumerSecret, null, null, $normalizedUrl, $normalizedRequestParameters);
		$doc = new SimpleXMLElement($this->GetQueryResponse($normalizedUrl, $normalizedRequestParameters . '&' . OAuthBase::$OAUTH_SIGNATURE . '=' . urlencode($signature)));       	        
		
		$this->ErrorCheck($doc);
		
		$json = json_encode($doc);
		
		$callback($json);
	}
	
	/* Search recipe
	* @param $recipe_id {string} the unique food identifier
	*/
	
	// public method are made available to the network
	public function getRecipe($recipe_id,$callback){
	
		$user_id = null;
		$token = null;
		$secret = null;
	
		$url = FatSecretAPI::$base.'method=recipe.get&recipe_id='.$recipe_id;  
		if (!empty($user_id)) $url .= '&user_id='.$user_id;
		
		$oauth = new OAuthBase();
	
		$normalizedUrl;
		$normalizedRequestParameters;
		
		$signature = $oauth->GenerateSignature($url, $this->_consumerKey, $this->_consumerSecret, null, null, $normalizedUrl, $normalizedRequestParameters);
		$doc = new SimpleXMLElement($this->GetQueryResponse($normalizedUrl, $normalizedRequestParameters . '&' . OAuthBase::$OAUTH_SIGNATURE . '=' . urlencode($signature)));       	        
		
		$this->ErrorCheck($doc);
		
		$json = json_encode($doc);
		
		$callback($json);
	}
	
	
	/* Private Methods */
	private function GetQueryResponse($requestUrl, $postString) {
		$ch = curl_init();
		
		curl_setopt($ch, CURLOPT_URL, $requestUrl);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postString);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		
        $response = curl_exec($ch);

        curl_close($ch);
		
		return $response;
	}
	
	private function ErrorCheck($doc){
		if($doc->getName() == 'error')
		{
			throw new FatSecretException((int)$doc->code, $doc->message);
		}
	}
	
		   
}

class FatSecretException extends Exception{
	
    public function FatSecretException($code, $message)
    {
        parent::__construct($message, $code);
    }
}

/* OAuth */
class OAuthBase {
	/* OAuth Parameters */
	static public $OAUTH_VERSION_NUMBER = '1.0';
	static public $OAUTH_PARAMETER_PREFIX = 'oauth_';
	static public $XOAUTH_PARAMETER_PREFIX = 'xoauth_';
	static public $PEN_SOCIAL_PARAMETER_PREFIX = 'opensocial_';

	static public $OAUTH_CONSUMER_KEY = 'oauth_consumer_key';
	static public $OAUTH_CALLBACK = 'oauth_callback';
	static public $OAUTH_VERSION = 'oauth_version';
	static public $OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';
	static public $OAUTH_SIGNATURE = 'oauth_signature';
	static public $OAUTH_TIMESTAMP = 'oauth_timestamp';
	static public $OAUTH_NONCE = 'oauth_nonce';
	static public $OAUTH_TOKEN = 'oauth_token';
	static public $OAUTH_TOKEN_SECRET = 'oauth_token_secret';
	
	protected $unreservedChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~';
	
	function GenerateSignature($url, $consumerKey, $consumerSecret, $token, $tokenSecret, &$normalizedUrl, &$normalizedRequestParameters){
		$signatureBase = $this->GenerateSignatureBase($url, $consumerKey, $token, 'POST', $this->GenerateTimeStamp(), $this->GenerateNonce(), 'HMAC-SHA1', $normalizedUrl, $normalizedRequestParameters);
        $secretKey = $this->UrlEncode($consumerSecret) . '&' . $this->UrlEncode($tokenSecret);
		return base64_encode(hash_hmac('sha1', $signatureBase, $secretKey, true));
	}
	
	private function GenerateSignatureBase($url, $consumerKey, $token, $httpMethod, $timeStamp, $nonce, $signatureType, &$normalizedUrl, &$normalizedRequestParameters){		
		$parameters = array();
		
		$elements = explode('?', $url);
		$parameters = $this->GetQueryParameters($elements[1]);
		
		$parameters[OAuthBase::$OAUTH_VERSION] = OAuthBase::$OAUTH_VERSION_NUMBER;
		$parameters[OAuthBase::$OAUTH_NONCE] = $nonce;
		$parameters[OAuthBase::$OAUTH_TIMESTAMP] = $timeStamp;
		$parameters[OAuthBase::$OAUTH_SIGNATURE_METHOD] = $signatureType;
		$parameters[OAuthBase::$OAUTH_CONSUMER_KEY] = $consumerKey;
		
		if(!empty($token)){
			$parameters[ OAuthBase::$OAUTH_TOKEN] = $token;
		}
		
		$normalizedUrl = $elements[0];
		$normalizedRequestParameters = $this->NormalizeRequestParameters($parameters);
		
		return $httpMethod . '&' . UrlEncode($normalizedUrl) . '&' . UrlEncode($normalizedRequestParameters);
	}
	
    private function GetQueryParameters($paramString) {
        $elements = split('&',$paramString);
        $result = array();
        foreach ($elements as $element)
        {
            list($key,$token) = split('=',$element);
            if($token)
                $token = urldecode($token);
            if(!empty($result[$key]))
            {
                if (!is_array($result[$key]))
                    $result[$key] = array($result[$key],$token);
                else
                    array_push($result[$key],$token);
            }
            else
                $result[$key]=$token;
        }

        return $result;
    }

    private function NormalizeRequestParameters($parameters) {
        $elements = array();
        ksort($parameters);

        foreach ($parameters as $paramName=>$paramValue) {
            array_push($elements,$this->UrlEncode($paramName).'='.$this->UrlEncode($paramValue));
        }
        return join('&',$elements);
    }
	
    private function UrlEncode($string) {
        $string = urlencode($string);
        $string = str_replace('+','%20',$string);
        $string = str_replace('!','%21',$string);
        $string = str_replace('*','%2A',$string);
        $string = str_replace('\'','%27',$string);
        $string = str_replace('(','%28',$string);
        $string = str_replace(')','%29',$string);
        return $string;
    }

	private function GenerateTimeStamp(){
		return time();
	}
	
	private function GenerateNonce(){
		return md5(uniqid());
	}
}

$loop = new React\EventLoop\StreamSelectLoop();

// Creat a DNode Server
$server = new DNode\DNode($loop, new FatSecretAPI(API_KEY, API_SECRET));
$server->listen(8811,'0.0.0.0');


echo "FatSecretAPI server listen on port 8811";

$loop->run();



?>