<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<?php
require_once("function.php");

$action = 0;
if(isset($_POST["_type"]))
{
  $action = $_POST["_type"];
}

$page = 0;
if(isset($_GET["page"]))
{
  $page = $_GET["page"];
}


?>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=ISO-8859-2"/>
	<link rel="Stylesheet" type="text/css" href="style.css" />
	<title>Account Panel</title>
</head>
<body>
<center>
<?php

echo '<h2><a href="'.$serverUrl.'" alt="Home">'.$serverName.'</a></h2>';

switch($action)
{
  case 1:
  {
    RequestCreateAccount();
    break;
  }
  case 2:
  {
    RequestChangePassword();
    break;
  }
  case 3:
  {
    RequestResetPassword();
    break;
  }
}

if($action == 0)
{
  switch($page)
  {
    case 0:
    {
      echo ShowMenu();
      break;
    }
    case 1:
    {
      echo ShowCreateAccount();
      break;
    }
    case 2:
    {
      echo ShowChangePassword();
      break;
    }
    case 3:
    {
      echo ShowResetPassword();
      break;
    }
  }
}

?>
<br><br><br><br>
Scripted by <a href="http://www.l2enigma.ar" alt="L2Service">L2EnigmA.ar</a> &copy; 2024.
</center>
</body>
</html>