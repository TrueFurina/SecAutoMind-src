<?php

	// 定义一个函数getIP()
	function getIP(){
		global $ip;
		if (getenv("HTTP_CLIENT_IP"))
			$ip = getenv("HTTP_CLIENT_IP");
		else if(getenv("HTTP_X_FORWARDED_FOR"))
			$ip = getenv("HTTP_X_FORWARDED_FOR");
		else if(getenv("REMOTE_ADDR"))
			$ip = getenv("REMOTE_ADDR");
		else $ip = "Unknow";
		return $ip;
	}

	header('Content-Type: text/html; charset=utf-8'); //网页编码

	if(getallheaders()){
		//获取当前长度
		$header_arr = getallheaders();

		$Content_Length =  @$header_arr['Content-Length'];
	}

	//考察绕waf的基本能力
	if(@getIP()=='127.0.0.1'&&$Content_Length > 1024){
		header("Location: ac50eec324f2acd7bfb2f5c91c4b62d9.html");
		// echo "flag{MBeGEaS67008RGb9}";
	}elseif(@getIP()=='127.0.0.1'){
		echo 'WAF拦截中';
	}else{
		echo "只有本地管理员才能访问本页面！";
	}

?>
