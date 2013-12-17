<?php
//github.com/stefan2200/firewall/
//GPLv3
//Free To Use

//use strip(value); to existing parameters
header("request-filtered-by: stefan2200-waf");
header("X-Frame-Options: SAMEORIGIN");

foreach ($_POST as $param_name => $param_val) {
    check($param_name, $param_val, "POST");
}
foreach ($_GET as $param_name => $param_val) {
    check($param_name, $param_val, "GET");
}
foreach ($_COOKIE as $param_name => $param_val) {
    check($param_name, $param_val, "COOKIE");
}
function strip($value){
 check("CUSTOM", $value, "HEADER");
}
function check($name, $value, $method){ //easy to add
 $var = trim($value);
 $var = addslashes($var);
  $tmpvar = strtolower($var);
  if (strpos($tmpvar, "'") == false && strpos($tmpvar, "*") == false && strpos($tmpvar, "--") == false){
   $var = stripslashes($var);
  }else{
   quit("SQL Statements in input detected!", $method);
  $var = NULL;
  }
  if (strpos($tmpvar, "<script>") == false && strpos($tmpvar, "\"") == false && strpos($tmpvar, "prompt(") == false && strpos($tmpvar, "alert(") == false){
   $var = stripslashes($var);
  }else{
   quit("XSS statements in input detected!", $method);
  $var = NULL;
  }
  if (strpos($tmpvar, "/./") == false && strpos($tmpvar, "etc/passwd") == false && strpos($tmpvar, "/..") == false && strpos($tmpvar, "/../") == false){
   $var = stripslashes($var);
  }else{
   quit("Path Traversal injection found!", $method);
  $var = NULL;
  }
}

function quit($msg, $method){
  header("400 Bad Request");
  header("firewall-message: request blocked");
 echo "<head><title>Error 400 - Bad Request</title><h1>".$method." Request Blocked!</h1></head><body><h2>".$msg."</h2><hr /><br />";
 /*$time = time();
 $code = rand(1,99999999);
  $log = $_SERVER['REMOTE_ADDR'];
  file_put_contents("waflogs/".date("d-m-y-H:m:i")."-".$code.".log", $log); */
  echo "<br />ip:".$_SERVER['REMOTE_ADDR']."<br />";
  exit();
 }
?>
