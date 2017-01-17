<?php
// 2014-09-04
if ($_SERVER['HTTP_HOST'] == 'XX.XX.XX.XX'){
	header("HTTP/1.1 301 Moved Permanently");
	header("Location: http://XX.XX.XX.XX/");
	die('<script type="text/javascript">window.location.href="http://XX.XX.XX.XX/";</script>');
}else if ($_SERVER['HTTP_HOST'] == 'DOMAIN.COM'){
	header("HTTP/1.1 301 Moved Permanently");
	header("Location: http://DOMAIN.COM/");
	die('<script type="text/javascript">window.location.href="http://DOMAIN.COM/";</script>');
}else if($_SERVER['HTTP_HOST'] == 'www.DOMAIN.COM'){
	header("HTTP/1.1 301 Moved Permanently");
	header("Location: http://www.DOMAIN.COM/");
	die('<script type="text/javascript">window.location.href="http://www.DOMAIN.COM/";</script>');
}

?>
<?php
$SERVER_DOMAIN_MAIN = "DOMAIN.COM";
$SERVER_DOMAIN_PREFIX = "x";
$SERVER_DOMAIN_SUFFIX = "p";
if ($_SERVER['HTTPS']=='on'){
	$SERVER_DOMAIN_HTTPS = "https";
}else{
	$SERVER_DOMAIN_HTTPS = "http";
	header('HTTP/1.1 500 Internal Server Error');
	die();
}
$SERVER_CACHE_PREFIX = "host/cachehost";
$SERVER_LONGURL_PREFIX = "longhost";
$SERVER_LONGURL_PRELEN = strlen($SERVER_LONGURL_PREFIX);
$SERVER_DEFAULT_URL = "http://www.bing.com/";
$userhash = sprintf("%x", crc32($_SERVER['REMOTE_ADDR']."_salt_".$_SERVER['HTTP_USER_AGENT']));
/////////////////////////////////////////////////////////////////////////////////////////////////////////
function hostencode($rawhost){
	global $SERVER_DOMAIN_MAIN;
	global $SERVER_LONGURL_PREFIX;
	global $SERVER_CACHE_PREFIX;
	global $SERVER_LONGURL_PRELEN;
	global $userhash;
	global $SERVER_DOMAIN_SUFFIX;
	global $SERVER_DOMAIN_PREFIX;
	$rawhost = strtolower($rawhost);
	if(strpos($rawhost,$SERVER_DOMAIN_MAIN,0) == FALSE){
		$enchost = "";
		if (preg_match("/^[a-zA-Z0-9\/\-\.:@]+$/", $rawhost)) {
			if(strlen($rawhost)>=42){
				$enchost = $SERVER_LONGURL_PREFIX.md5($rawhost);
				$cachehost = $SERVER_CACHE_PREFIX.".".$enchost.".cache";
				if (!file_exists($cachehost)){
					file_put_contents ($cachehost, $rawhost);
				}
			}else{
				//if(empty($input)) return "";
				$input = str_split($rawhost);
				$i = 0;
				while($i<count($input)){
					//print($input[$i]);
					if     ($input[$i]=="."){				$enchost .= "z";
					}elseif($input[$i]==":"){				$enchost .= "j";
					}elseif($input[$i]=="/"){				$enchost .= "q";
					}elseif($input[$i]=="x"){				$enchost .= "x1";
					}elseif($input[$i]=="z"){				$enchost .= "x2";
					}elseif($input[$i]=="j"){				$enchost .= "x3";
					}elseif($input[$i]=="q"){				$enchost .= "x4";
					}elseif($input[$i]=="-"){				$enchost .= "x5";
					}elseif($input[$i]=="@"){				$enchost .= "x6";
					
					}elseif($input[$i]=="t"){				$enchost .= "h";
					}elseif($input[$i]=="a"){				$enchost .= "s";
					}elseif($input[$i]=="o"){				$enchost .= "r";
					}elseif($input[$i]=="i"){				$enchost .= "n";
					}elseif($input[$i]=="n"){				$enchost .= "i";
					}elseif($input[$i]=="r"){				$enchost .= "o";
					}elseif($input[$i]=="s"){				$enchost .= "a";
					}elseif($input[$i]=="h"){				$enchost .= "t";
					
					}else{									$enchost .= $input[$i];
					}
					$i++;
				}
				//$enchost = strtr($rawhost, 
				//							':/-.!@#$%&*_+=~|;?,\\', 
				//							'QAZWSXEDCRFVTGBYHNUJ');
			}
		}
	}else{
		$hostpieces = explode("-", $rawhost);
		//print_r($hostpieces);
		if(count($hostpieces)==5 and $hostpieces[4]==$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN and $hostpieces[1]==$userhash){
			$enchost = $hostpieces[2];
		}
	}
	return $enchost;
}
function hostdecode($rawhost){
	global $SERVER_LONGURL_PREFIX;
	global $SERVER_CACHE_PREFIX;
	global $SERVER_LONGURL_PRELEN;
	$rawhost = strtolower($rawhost);
	$dechost = "";
	if(strlen($rawhost) == ($SERVER_LONGURL_PRELEN + 32) and substr($rawhost,0,$SERVER_LONGURL_PRELEN) == $SERVER_LONGURL_PREFIX){
		$cachehost = $SERVER_CACHE_PREFIX.".".$rawhost.".cache";
		if (file_exists($cachehost)){
			$dechost = file_get_contents($cachehost);
		}
	}else{
		$input = str_split($rawhost);
		$i = 0;
		while($i<count($input)){
			if     ($input[$i]=="z"){				$dechost .= ".";
			}elseif($input[$i]=="j"){				$dechost .= ":";
			}elseif($input[$i]=="q"){				$dechost .= "/";
			}elseif($input[$i]=="x"){
				$i++;
				if($i < count($input)){
					if(   $input[$i] == "1"){				$dechost .= "x";
					}elseif($input[$i]=="2"){				$dechost .= "z";
					}elseif($input[$i]=="3"){				$dechost .= "j";
					}elseif($input[$i]=="4"){				$dechost .= "q";
					}elseif($input[$i]=="5"){				$dechost .= "-";
					}elseif($input[$i]=="6"){				$dechost .= "@";
					}else{									$dechost = "";break;
					}
				}else{										$dechost = "";break;
				}
			}elseif($input[$i]=="t"){				$dechost .= "h";
			}elseif($input[$i]=="a"){				$dechost .= "s";
			}elseif($input[$i]=="o"){				$dechost .= "r";
			}elseif($input[$i]=="i"){				$dechost .= "n";
			}elseif($input[$i]=="n"){				$dechost .= "i";
			}elseif($input[$i]=="r"){				$dechost .= "o";
			}elseif($input[$i]=="s"){				$dechost .= "a";
			}elseif($input[$i]=="h"){				$dechost .= "t";
			}else{									$dechost .= $input[$i];
			}
			$i++;
		}
		//$dechost = strtr($rawhost, 
		//							'QAZWSXEDCRFVTGBYHNUJ', 
		//							':/-.!@#$%&*_+=~|;?,\\');
	}
	return $dechost;
}
class light_url_base{
	var $p = "#";
	var $s = "#";
	function __construct($prefix,$subfix){
		$this->p = $prefix;
		$this->s = $subfix;
	}
	function enc($u){
		$p = explode("/", $u,4);
		if (in_array(strtolower($p[0]), array("http:", "https:", "ftp:"))){
			$h = hostencode($p[0]."//".$p[2]);
			$r = "";
			if (count($p)==4){$r .= "/".$p[3];}
			return $this->p.$h.$this->s.$r;
		}else{
			return $u;
		}
	}
	function dec($u){
		global $SERVER_DOMAIN_MAIN;
		$p = explode("/", $u,4);
		$q = explode("-", strtolower($p[2]));
		$h = hostdecode($q[2]);
		if ($h != ""){
			$r = "";
			if (count($p)==4){$r .= "/".$p[3];}
			$u = $h.$r;
			if (strpos($host,$SERVER_DOMAIN_MAIN,0) == FALSE){
				return $u;
			}else{
				return dec($u);
			}
		}else{
			return "";
		}
	}
}
function locationhref($newurl){
	header('Location: '.$newurl.'');
	echo '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="refresh" content="1; url='.$newurl.'" />
<title>Web Browser</title></head><body><a href="'.$newurl.'" >'.$newurl.'</a>
<script language="JavaScript" type="text/javascript">location.href=\''.$newurl.'\';</script></body></html>';
	die();
}
function locationhref_test($newurl){
	echo '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Web Browser</title></head><body><a href="'.$newurl.'" >'.$newurl.'</a></body></html>';
	die();
}
function urlreplace($js){
	//print($js);
	global $LightUrlEnc;
	$arr = array('://',':\\/\\/',':\\\\\\/\\\\\/');
	foreach($arr as $key => $val){
		$fndstr = $val;
		$fndlen = strlen($fndstr);
		//print $fndstr;
		$newjs = "";
		$ptr = 0;
		$len = strlen($js);
		while(1){
			$tag = strpos($js,$fndstr,$ptr);
			if ($tag > 5){
				$prot = "";
				if($tag>=4 and substr($js,$tag-4,4)=="http"){
					$prot = "http://";
					$pos = $tag-4;
				}elseif($tag>=3 and substr($js,$tag-3,3)=="ftp"){
					$prot = "ftp://";
					$pos = $tag-3;
				}elseif($tag>=5 and substr($js,$tag-5,5)=="https"){
					$prot = "https://";
					$pos = $tag-5;
				}else{
					$pos = $tag;
				}
				$faild = TRUE;
				if ($pos > $ptr and $pos < $tag){
					$tmpbuff = substr($js,$tag+$fndlen,min(255,$len-$tag));
					//print "<!------------------------------------------------------------------------------!>\n".$prot."\n".$tmpbuff."\n<br/>\n";
					if(preg_match('/^([a-zA-Z0-9\.\-]+)/',$tmpbuff,$matches)){
						$host = $matches[1];
						//print_r($matches)."\n<br/>\n";
						if(strpos($host,".",0) > 0 and strpos($host,".w3.org",0) == FALSE){
							$newhost = $LightUrlEnc->enc($prot.$host);
							//$newjs .= substr($js,$ptr,$pos-$ptr).$newhost;
							$newjs .= substr($js,$ptr,$pos-$ptr).str_replace("://",$fndstr,$newhost);
							$ptr = $tag + $fndlen + strlen($host);
							$faild = FALSE;
						}
					}
				}
				if ($faild == TRUE){
					$newjs .= substr($js,$ptr,$tag+$fndlen-$ptr);
					$ptr = $tag+$fndlen;
				}
			}else{
				$newjs .= substr($js,$ptr,$len-$ptr);
				break;
			}
		}
		$js = $newjs;
	}
	return $js;
}
function urlreplace_fix1($protocol,$js){//sometimes  action="//www.com/"
	//return $js;
	//print($js);
	global $LightUrlEnc;
	//eplace(/\.(action|src|location|href)\s*=\s*([^;}]+)/ig,'.$1=parseURL($2)');
	$arr = array('src=','href=','action=');
	foreach($arr as $key => $val){
		$fndstr = $val;
		$fndlen = strlen($fndstr);
		//print $fndstr;
		$newjs = "";
		$ptr = 0;
		$len = strlen($js);
		while(1){
			$tag = stripos($js,$fndstr,$ptr);//case
			if ($tag > 0 and $tag+$fndlen +3 < $len){
				$prot = "";
				if(substr($js,$tag+$fndlen,2)=="//"){
					$pos = $tag + $fndlen;
					$prot = $protocol . "//";
				}elseif(substr($js,$tag+$fndlen+1,2)=="//"){
					$pos = $tag + $fndlen + 1;
					$prot = $protocol . "//";
				}
				$faild = TRUE;
				if ($prot != "" and $pos > $tag){
					$tmpbuff = substr($js,$pos + 2,min(255,$len - 2 -$pos));
					//print "<!------------------------------------------------------------------------------!>\n".$prot."\n".$tmpbuff."\n<br/>\n";
					if(preg_match('/^([a-zA-Z0-9\.\-]+)/',$tmpbuff,$matches)){
						$host = $matches[1];
						//print_r($matches)."\n<br/>\n";
						if(strpos($host,".",0) > 0 and strpos($host,".w3.org",0) == FALSE){
							$newhost = $LightUrlEnc->enc($prot.$host);
							//$newjs .= substr($js,$ptr,$pos-$ptr).$newhost;
							$newjs .= substr($js,$ptr,$pos-$ptr).$newhost;
							$ptr = $pos + 2 + strlen($host);
							$faild = FALSE;
						}
					}
				}
				if ($faild == TRUE){
					$newjs .= substr($js,$ptr,$tag+$fndlen-$ptr);
					$ptr = $tag+$fndlen;
				}
			}else{
				$newjs .= substr($js,$ptr,$len-$ptr);
				break;
			}
		}
		$js = $newjs;
	}
	return $js;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
$pieces = explode("-", strtolower($_SERVER['SERVER_NAME']));
$initaction = "";
if (count($pieces)==1){
	$initaction = "default";
}elseif ( $_SERVER['SERVER_NAME'] == $SERVER_DOMAIN_PREFIX."-init-".$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN and isset($_POST['url'])){
	$initaction = "init";
}elseif (count($pieces)==4 and $pieces[0]==$SERVER_DOMAIN_PREFIX and $pieces[3]==$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN and $pieces[1]==$userhash ){
	$initaction = $pieces[2];
}elseif (count($pieces)==5 and $pieces[0]==$SERVER_DOMAIN_PREFIX and $pieces[4]==$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN and $pieces[1]==$userhash){
	$initaction = "proxy";
}else{
	header('HTTP/1.1 404 Not Found');
	die();
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
switch($initaction){
	case 'proxy':
		$realhost = hostdecode($pieces[2]);
		if (strlen($realhost)>5){
			$hostpieces = explode("/", $realhost,4);
			$protocol = strtolower($hostpieces[0]);
			if (in_array($protocol, array("http:", "https:", "ftp:"))){
				$url = $realhost.$_SERVER['REQUEST_URI'];
				$flag = intval($pieces[3]);
				$LightUrlEnc = new light_url_base($SERVER_DOMAIN_HTTPS."://".$pieces[0]."-".$pieces[1]."-","-".intval($pieces[3])."-".$pieces[4]);
				require_once('module_http.php');
				$knHTTP = new knHttp($url);
				$knHTTP->set_post($_POST);
				$knHTTP->set_cookies($_COOKIE);
				if(isset($_SERVER['PHP_AUTH_USER']                          )){$knHTTP->set_http_creds($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW']);}
				if(isset($_SERVER['HTTP_IF_MODIFIED_SINCE'  ]               )){$knHTTP->set_request_headers(Array('If-Modified-Since',$_SERVER['HTTP_IF_MODIFIED_SINCE']));}
				if(isset($_SERVER['HTTP_IF_MATCH']                          )){$knHTTP->set_request_headers(Array('If-Match',$_SERVER['HTTP_IF_MATCH']));}
				if(isset($_SERVER['HTTP_IF_NONE_MATCH']                     )){$knHTTP->set_request_headers(Array('If-None-Match',$_SERVER['HTTP_IF_NONE_MATCH']));}
				if(isset($_SERVER['HTTP_IF_UNMODIFIED_SINCE']               )){$knHTTP->set_request_headers(Array('If-Unmodified-Since',$_SERVER['HTTP_IF_UNMODIFIED_SINCE']));}
				if(isset($_SERVER['HTTP_IF_RANGE']                          )){$knHTTP->set_request_headers(Array('If-Range',$_SERVER['HTTP_IF_RANGE']));}
				if(isset($_SERVER['HTTP_RANGE']                             )){$knHTTP->set_request_headers(Array('Range',$_SERVER['RANGE']));}
				if(isset($_SERVER['HTTP_ACCEPT_LANGUAGE']                   )){$knHTTP->set_request_headers(Array('Accept-Language:',$_SERVER['HTTP_ACCEPT_LANGUAGE']));}
				if(isset($_SERVER['HTTP_REFERER']) and ($flag & 0x02) == 0x02){$knHTTP->set_referer($LightUrlEnc->dec($_SERVER['HTTP_REFERER']));}
				//echo(  $LightUrlEnc->dec($_SERVER['HTTP_REFERER'])   );
				$knHTTP->send();
				
				$headers = $knHTTP->refined_headers();
				if(!isset($headers["HTTP_RESPONSE"])){
					header('HTTP/1.1 500 Internal Server Error');
					exit();
				}
				if($headers['HTTP_RESPONSE']==401){
					//UNAUTHORIZED
					$realm = $headers['WWW_AUTHENTICATE_REALM'];
					header('WWW-Authenticate: Basic realm=".$realm."');
					header('HTTP/1.0 401 Unauthorized');
				}else{
					header('HTTP/1.1 ' . $headers['HTTP_RESPONSE'] . ' Omitted');
				}
				header('Content-Type: ' . $knHTTP->doctype);
				if(isset($headers['HTTP_LOCATION']) && $headers['HTTP_LOCATION']!=''            ){header('Location: ' . $LightUrlEnc->enc($headers['HTTP_LOCATION']) );}
				if(isset($headers['CONTENT_DISPOSITION']) && $headers['CONTENT_DISPOSITION']!=''){header('Content-Disposition: ' . $headers['CONTENT_DISPOSITION']);}
				if(!empty($headers['CACHE_CONTROL'])                                            ){header('Cache-Control: ' . $headers['CACHE_CONTROL']);}
				if(!empty($headers['EXPIRES'])                                                  ){header('Expires: ' . $headers['EXPIRES']);}
				if(!empty($headers['ACCEPT_RANGES'])                                            ){header('Accept-Ranges: ' . $headers['ACCEPT_RANGES']);}
				if(!empty($headers['CONTENT_RANGE'])                                            ){header('Content-Range: ' . $headers['CONTENT_RANGE']);}
				if(isset($headers['HTTP_REFRESH'])                                              ){header('refresh:'.(int)$headers['refresh'][0].';url='. $LightUrlEnc->enc($headers['refresh'][1]));}
				$page_data = $knHTTP->content;
				$mime_type = $knHTTP->doctype;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$this_type=preg_replace('~\s~','',preg_replace('~;.*$~','',$mime_type));
if($this_type == ""){
	if($url != null){
		if(preg_match("~\.(.+)$~",$url,$m)){
			switch($m[1]){
				case "css":$this_type = "text/css";break;
				case "js":$this_type = "text/javascript";break;
				case "htm":
				case "html":$this_type = "text/html";break;
				case "txt":$this_type = "text/txt";break;
				default:$this_type = "";
			}
		}
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$this_charset = "";
if(preg_match('~^.*;\s*charset\s*=\s*([a-zA-Z0-9\-]*)\s*[;]*$~',$mime_type,$matches)){
	$this_charset = $matches[1];
}
if($this_charset==""){
	preg_match('~<meta.*charset=(.+)["\'].*\>~iUs',$page_data,$pmatch);
	if(count($pmatch)>0)
		$this_charset = $pmatch[1];
	
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$this_output = "";
$repflag=FALSE;
switch($this_type){
	case 'text/css':$this_output = urlreplace($page_data);break;
	//case 'text/css':$this_output = cssParse($page_data);break;
	case 'text/javascript':
	case 'application/javascript':
	case 'application/x-javascript':if(($flag & 0x04) == 0x00){$this_output = urlreplace($page_data);}break;
	//case 'application/x-javascript':$this_output = jsParse($page_data);break;
	case 'video/mp4':
	case 'image/gif':
	case 'image/png':
	case 'image/jpeg':$this_output = $page_data;break;
	case 'text/html':$this_output = urlreplace_fix1($protocol,urlreplace($page_data));$repflag=TRUE;break;
	//case 'text/html':$this_output = HTMLparse($page_data);break;
	default:{
		if(substr($this_type,0,6)=='video/' || substr($this_type,0,6)=='audio/' || substr($this_type,0,12)=='application/'){
			$this_output = $page_data;
		}else{
			$repflag=TRUE;
			$this_output = urlreplace_fix1($protocol,urlreplace($page_data));
			//$this_output = HTMLparse($page_data);
		}
	}break;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
if(defined('KNPROXY_USE_GZIP') && KNPROXY_USE_GZIP == 'true' && substr_count($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip') && function_exists('ob_gzhandler')){
	if(substr($this_type,0,5)=='text/'){
		ob_start("ob_gzhandler");
		echo $this_output;
	}else
		echo $this_output;
}else{
	echo $this_output;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
				exit();
			}
		}
		break;
	case 'init':
		$urlpieces = explode("/", $_POST['url'],4);
		$encodedauth = $_POST['auth'];
		$encodedflag = 0;
		if(isset($_POST['flag'])){foreach ($_POST['flag'] as $k=>$v){$encodedflag += intval($v);}}
		if ($encodedauth == $userhash){
			if (count($urlpieces)>=3){
				if ($urlpieces[1] == ""){
					$encodedhost = hostencode($urlpieces[0]."//".$urlpieces[2]);
					if(strlen($encodedhost)>0){
						$encodeduri = "/";
						if (count($urlpieces)==4){$encodeduri .= $urlpieces[3];}
						$newurl = $SERVER_DOMAIN_HTTPS."://".$SERVER_DOMAIN_PREFIX."-".$encodedauth."-".$encodedhost."-".$encodedflag."-".$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN.$encodeduri;
						echo locationhref($newurl); 
						exit();
					}
				}
			}
		}else{
			echo "auth error";
			exit();
			break;
		}
	case 'default':
		if($_SERVER['SERVER_NAME'] == "xxxxxxxxxxxxxx.".$SERVER_DOMAIN_MAIN){
			$perinputuserhash = $userhash;
		}
		echo '<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Web Browser</title>
</head>
<body>
<style type="text/css">
BODY,form,input {MARGIN: 0px; PADDING-BOTTOM: 0px; PADDING-LEFT: 0px; PADDING-RIGHT: 0px; PADDING-TOP: 0px}
body
{
 text-align:center; 
}
/*
table{border-right:2px solid #000;border-bottom:2px solid #000;border-top:2px solid #000;border-left:2px solid #000;}
td{border-right:1px solid #000;border-bottom:1px solid #000;border-top:1px solid #000;border-left:1px solid #000;}
table{border-right:2px #000;border-bottom:2px #000;border-top:2px #000;border-left:2px #000;}
td{border-right:1px #000;border-bottom:1px #000;border-top:1px #000;border-left:1px #000;}
*/

</style>
<h1 align="center">Web Browser</h1>
<form name="login" action="'.$SERVER_DOMAIN_HTTPS."://".$SERVER_DOMAIN_PREFIX."-init-".$SERVER_DOMAIN_SUFFIX.".".$SERVER_DOMAIN_MAIN.'/" method="POST">
<form action="/" method="post" enctype="multipart/form-data">
URL:<input type="text" name="url" value="'.$SERVER_DEFAULT_URL.'" size="128"/><input type="submit" value="Go" /><br/>
<font color=gray size=2>AUTH:<input type="text" name="auth" value="'.$perinputuserhash.'" size="12"/>
&nbsp;<label><input name="flag[]" type="checkbox" value="1" />SSL_VERIFY</label>
&nbsp;<label><input name="flag[]" type="checkbox" value="2" />HTTP_REFERER</label>
&nbsp;<label><input name="flag[]" type="checkbox" value="4" />REMOVE_SCRIPT</label>
</font>
</form>
</body>
</html>';
		//echo "<pre>\n";
		//echo "crc32('".($_SERVER['REMOTE_ADDR']."'+'".$_SERVER['HTTP_USER_AGENT'])."')=".sprintf("%x", crc32($_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']));
		//echo "<hr>\n";
		//echo 'HTTP_HOST   '.$_SERVER['HTTP_HOST']."<br>\n"; 
		//echo 'PHP_SELF    '.$_SERVER['PHP_SELF']."<br>\n"; 
		//echo 'QUERY_STRING'.$_SERVER['QUERY_STRING']."<br>\n"; 
		//echo 'HTTP_REFERER'.$_SERVER['HTTP_REFERER']."<br>\n"; 
		//echo 'HTTPS       '.$_SERVER['HTTPS']."<br>\n"; 
		//echo 'SERVER_NAME '.$_SERVER['SERVER_NAME']."<br>\n"; 
		//echo 'SERVER_PORT '.$_SERVER['SERVER_PORT']."<br>\n"; 
		//echo 'REQUEST_URI '.$_SERVER['REQUEST_URI']."<br>\n";  
		//echo "<hr>\n";
		//echo $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']."<br>\n";
		//echo "<hr>\n";
		exit();
		break;
	default:
		header('HTTP/1.1 500 Internal Server Error');
		die();
		break;
}
header('HTTP/1.1 500 Internal Server Error');
die();
?>
