<?php
include('config.php');
require_once('captcha.php');

class Packet
{
  private $buff = "";
  private $len = 0;
  
  public function WriteS($text)
  {
    $count = strlen($text);
    for($n=0;$n<$count;$n++)
    {
      $this->buff .= $text[$n];
    }
    $this->buff .= "\0";
    $this->len += $count + 1;
  }
  public function WriteC($value)
  {
    $this->buff .= pack('c', $value);
    $this->len += 1;
  }
  public function WriteD($value)
  {
    $this->buff .= pack('l', $value);
    $this->len += 4;
  }
  public function GetBuff()
  {
    return $this->buff;
  }
  public function GetLen()
  {
    return $this->len;
  }
  public function SendTo($sock)
  {
    if($this->len > 0)
    {
      $totalLen = 2 + $this->len;
      fwrite($sock, pack("s", $totalLen) . $this->buff);
    }
  }
};

class PacketIn
{
  private $len = 0;
  private $sock;
  public function Init($socket)
  {
    $this->sock = $socket;
    list(, $value) = unpack ( "v", fread ( $this->sock, 2 ) );
    $this->len = $value;
    if($this->len > 0)
    {
      return true;
    }
    return false;
  }
  public function GetLen()
  {
    return $this->len;
  }
  public function ReadC()
  {
    list(, $value) = unpack("c", fread($this->sock, 1));
    return $value;
  }
  public function ReadD()
  {
    list(, $value) = unpack("l", fread($this->sock, 4));
    return $value;
  }
  public function ReadS()
  {
    $str = "";
    while(!feof($this->sock))
    {
      $str .= fread($this->sock, 1);
    }
    return $str;
  }
};

function ShowCaptcha()
{
	global $captchaType;
	
  $captchaId  = '1454';
	if($captchaType == 1)
	{
		$captchaId = '1471';
	}
  $publicKey  = '27407abc-f6dc-4ec2-a960-8f97f0cde93d';
  return GetCaptcha($captchaId, $publicKey); 
}

function IsValidCaptcha()
{
  global $captchaType;
  if(isset($_POST['_type']))
  {
    $captchaId  = '1454';
    $privateKey = '22f92520-9fc1-413a-94ff-21b52d805b0a';
    if($captchaType == 1)
    {
      $captchaId = '1471';
    }
    $challengeValue = $_POST['adscaptcha_challenge_field'];
    $responseValue  = $_POST['adscaptcha_response_field'];
    $remoteAddress  = $_SERVER["REMOTE_ADDR"];

    if ("true" == ValidateCaptcha($captchaId, $privateKey, $challengeValue, $responseValue, $remoteAddress))
    {
      return TRUE;
    }
  }
  return FALSE;
}

function encrypt( $plain )
{
  $array_mul = array ( 0 => 213119, 1 => 213247, 2 => 213203, 3 => 213821 );
  $array_add = array ( 0 => 2529077, 1 => 2529089, 2 => 2529589, 3 => 2529997 );
  $dst = $key = array ( 0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0, 15 => 0 );

  for ( $i = 0; $i < strlen ( $plain ); $i++ ) {
    $dst [ $i ] = $key [ $i ] = ord ( substr ( $plain, $i, 1 ) );
  }

  for ( $i = 0; $i <= 3; $i++ ) {
    $val [ $i ] = fmod ( ( $key [ $i * 4 + 0 ] + $key [ $i * 4 + 1 ] * 0x100 + $key [ $i * 4 + 2 ] * 0x10000 + $key [ $i * 4 + 3 ] * 0x1000000 ) * $array_mul [ $i ] + $array_add [ $i ], 4294967296 );
  }

  for ( $i = 0; $i <= 3; $i++ ) {
    $key [ $i * 4 + 0 ] = $val [ $i ] & 0xff;
    $key [ $i * 4 + 1 ] = $val [ $i ] / 0x100 & 0xff;
    $key [ $i * 4 + 2 ] = $val [ $i ] / 0x10000 & 0xff;
    $key [ $i * 4 + 3 ] = $val [ $i ] / 0x1000000 & 0xff;
  }

  $dst [ 0 ] = $dst [ 0 ] ^ $key [ 0 ];
  for ( $i = 1; $i <= 15; $i++ ) {
    $dst [ $i ] = $dst [ $i ] ^ $dst [ $i - 1 ] ^ $key [ $i ];
  }

  for ( $i = 0; $i <= 15; $i++ ) {
    if ( $dst [ $i ] == 0 ) {
      $dst [ $i ] = 0x66;
    }
  }

  $encrypted = "0x";
  for ( $i = 0; $i <= 15; $i++ ) {
    if ( $dst [ $i ] < 16 ) {
      $encrypted .= "0";
    }
    $encrypted .= /*strtoupper (*/ dechex ( $dst [ $i ] ) /*)*/;
  }
  return ( $encrypted );
}

function DBGetAccountId($login)
{
  global $dbHost, $dbPort;
  $sock = fsockopen($dbHost, $dbPort) or die('Cannot connect to: '.$dbHost);
  $packet = new Packet();
  $packet->WriteC(3);
  $packet->WriteS($login);
  $packet->SendTo($sock);
  //GetReply
  $pckIn = new PacketIn();
  if($pckIn->Init($sock))
  {
      $pckIn->ReadC();  //OpCode
      $accountId = $pckIn->ReadD(); //accountId
      fclose($sock);
      return $accountId;
  }
  fclose($sock);  
  return 0;  
}

//returns accountId if succeed
//-1 - already exists
// 0 - invalid params (login,pwd,email)
//-2 - db error
function DBCreateAccount($login, $password, $email)
{
  $accountId = 0;
  global $dbHost, $dbPort;
  $sock = fsockopen($dbHost, $dbPort) or die('Cannot connect to: '.$dbHost);
  $packet = new Packet();
  $packet->WriteC(0);
  $packet->WriteS($login);
  $packet->WriteS(encrypt($password));
  $packet->WriteS($email);
  $packet->SendTo($sock);
  
  $pckIn = new PacketIn();
  if($pckIn->Init($sock))
  {
    $pckIn->ReadC();  //OpCode
    $accountId = $pckIn->ReadD();
    $message = $pckIn->ReadS();
  }  
  fclose($sock);
  return $accountId;
}

//returns accountId when succeed, 0 - invalid params (login, passwordd, email or newPassword)
//-1 - email doesnt match
//-2 - Password doesnt match
//-3 - DB Error
function DBChanePassword($login, $password, $newPassword, $email)
{
  $accountId = 0;
  global $dbHost, $dbPort;
  $sock = fsockopen($dbHost, $dbPort) or die('Cannot connect to: '.$dbHost);
  $packet = new Packet();
  $packet->WriteC(1);
  $packet->WriteS($login);
  $packet->WriteS(encrypt($password));
  $packet->WriteS($email);
  $packet->WriteS(encrypt($newPassword));
  $packet->SendTo($sock);
  
  $pckIn = new PacketIn();
  if($pckIn->Init($sock))
  {
    $pckIn->ReadC();  //OpCode
    $accountId = $pckIn->ReadD();
    $message = $pckIn->ReadS();
  }  
  fclose($sock);
  return $accountId;
}

//returns accountId if succeed
// 0 - invalid params (login, email or newPassword)
//-1 - email doesn't match
//-2 - DB Error
function DBResetPassword($login, $email, $newPassword)
{
  $accountId = 0;
  global $dbHost, $dbPort;
  $sock = fsockopen($dbHost, $dbPort) or die('Cannot connect to: '.$dbHost);
  $packet = new Packet();
  $packet->WriteC(2);
  $packet->WriteS($login);
  $packet->WriteS($email);
  $packet->WriteS($newPassword);
  $packet->WriteS(encrypt($newPassword));
  $packet->SendTo($sock);
  
  $pckIn = new PacketIn();
  if($pckIn->Init($sock))
  {
    $pckIn->ReadC();  //OpCode
    $accountId = $pckIn->ReadD();
    $message = $pckIn->ReadS();
    if($message == 'Password has been changed!')
    {
			//mail the password
			echo "Password has been changed!!!!!!!!!!!!!!!<br>";
			echo $newPassword.'<br>';
    }
  }  
  
  return $accountId;
}

function ShowMenu()
{
  $html = '<h4><a href="index.php?page=1" id="apmenu">Create Account</a><br>
  <a href="index.php?page=2" id="apmenu">Change Password</a><br>
  <a href="index.php?page=3" id="apmenu">Reset Password</a><br></h4>';
  return $html;
}


function ShowCreateAccount()
{
  global $captchaType;
  $html = '<h2>Create Account</h2><br>
          <form action="index.php" id="apform" method="POST" >
          <b>Account name</b><br>
          Please enter your account name, alphanumeric characters (a-Z, 0-9)<br>
          <input type="text" id="apinput" name="_login"><br><br>
          <b>Password</b><br>
          Please enter your password ( <a href="http://www.microsoft.com/security/online-privacy/passwords-create.aspx" target="_blank" >stronger = better</a> )<br>
          <input type="password" id="apinput" name="_password"><br><br>
          <b>Confirm password</b><br>
          Please enter your password again<br>
          <input type="password" id="apinput" name="_password2"><br><br>
          <b>Email</b><br>
          Please enter your email address<br>
          <input type="text" id="apinput" name="_email"><br><br>
          <input type="hidden" name="_type" value="1">
          <b>Captcha</b><br>';
          
  if($captchaType == 1)
  {
    $html .= "Please fit the image<br>";
  }else
  {
    $html .= "Please enter the code<br>";
  }
  $html .= ShowCaptcha().'<br><br>
          <input type="submit" id="apsubmit" name="_submit" value="Create">
          </form>';
          
  return $html;
}

function IsValidLogin($login)
{
  $loginRegex = "/^[a-zA-Z0-9]{4,14}+$/";
  if(preg_match($loginRegex, $login))
  { 
    return TRUE;
  }
  return FALSE;
}

function IsValidPassword($password)
{
  $regex = "/^[a-zA-Z0-9]{4,14}+$/";
  if(preg_match($regex, $password))
  { 
    return TRUE;
  }
  return FALSE;
}

function IsValidEmail($email)
{
  $regex = "/^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-zA-Z.]{2,5}$/";
  if(preg_match($regex, $email))
  { 
    return TRUE;
  }
  return FALSE;
}

function RequestCreateAccount()
{
  $login = $_POST['_login'];
  $password = $_POST['_password'];
  $password2 = $_POST['_password2'];
  $email = $_POST['_email'];
  
  if(!IsValidLogin($login))
  {
    echo '<div style="color: red;">Invalid account name!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }
  if(!IsValidPassword($password))
  {
    echo '<div style="color: red;">Invalid password!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }
  if(!IsValidEmail($email))
  {
    echo '<div style="color: red;">Invalid email!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }
  if($password != $password2)
  {
    echo '<div style="color: red;">Confirmed password doesn\'t match!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }
  
  if(!IsValidCaptcha())
  {
    echo '<div style="color: red;">Captcha doesn\'t match!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }
  
  $accountId = DBCreateAccount($login, $password, $email);
  if($accountId > 0)
  {
    echo '<h2>Account has been created!</h2><br>';
    return TRUE;
  }else if($accountId == -1)
  {
    echo '<div style="color: red;">Account already exists!<br>Please try again.</div>';
    echo ShowCreateAccount();
    return FALSE;
  }else
  {
    echo '<div style="color: red;">Database Error!<br>Please try again later.</div>';
    return FALSE;
  }
}

function ShowChangePassword()
{
  global $captchaType;
  $html = '<h2>Change Password</h2><br>
          <form action="index.php" id="apform" method="POST" >
          <b>Account name</b><br>
          Please enter your account name, alphanumeric characters (a-Z, 0-9)<br>
          <input type="text" id="apinput" name="_login"><br><br>
          <b>Old password</b><br>
          Please enter your old password<br>
          <input type="password" id="apinput" name="_oldpassword"><br><br>
          <b>New password</b><br>
          Please enter your new password ( <a href="http://www.microsoft.com/security/online-privacy/passwords-create.aspx" target="_blank" >stronger = better</a> )<br>
          <input type="password" id="apinput" name="_newpassword"><br><br>
          <b>Confirm new password</b><br>
          Please enter your new password again<br>
          <input type="password" id="apinput" name="_newpassword2"><br><br>
          <b>Email</b><br>
          Please enter your email address<br>
          <input type="text" id="apinput" name="_email"><br><br>
          <input type="hidden" name="_type" value="2">
          <b>Captcha</b><br>';
          
  if($captchaType == 1)
  {
    $html .= "Please fit the image<br>";
  }else
  {
    $html .= "Please enter the code<br>";
  }
  $html .= ShowCaptcha().'<br><br>
          <input type="submit" id="apsubmit" name="_submit" value="Create">
          </form>';
          
  return $html;
}

function RequestChangePassword()
{
  $login = $_POST['_login'];
  $oldpassword = $_POST['_oldpassword'];
  $newpassword = $_POST['_newpassword'];
  $newpassword2 = $_POST['_newpassword2'];
  $email = $_POST['_email'];
  
  if(!IsValidLogin($login))
  {
    echo '<div style="color: red;">Invalid account name!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  if(!IsValidPassword($oldpassword))
  {
    echo '<div style="color: red;">Invalid old password!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  if(!IsValidPassword($newpassword))
  {
    echo '<div style="color: red;">Invalid new password!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  if(!IsValidEmail($email))
  {
    echo '<div style="color: red;">Invalid email!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  if($newpassword != $newpassword2)
  {
    echo '<div style="color: red;">Confirmed password doesn\'t match!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  
  if(!IsValidCaptcha())
  {
    echo '<div style="color: red;">Captcha doesn\'t match!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  
  $accountId = DBGetAccountId($login);
  if($accountId <= 0)
  {
    echo '<div style="color: red;">Account doesn\'t exist!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }
  
  $accountId = DBChanePassword($login, $oldpassword, $newpassword, $email);
  if($accountId > 0)
  {
    echo '<h2>Password has been changed!</h2><br>';
    return TRUE;
  }else if($accountId == -1)
  {
    echo '<div style="color: red;">Email doesn\'t match!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }else if($accountId == -2)
  {
    echo '<div style="color: red;">Password doesn\'t match!<br>Please try again.</div>';
    echo ShowChangePassword();
    return FALSE;
  }else
  {
    echo '<div style="color: red;">Database Error!<br>Please try again later.</div>';
    return FALSE;
  }
}

function GeneratePassword()
{
  $length = 8;

  list($usec, $sec) = explode(' ', microtime());
  $seed = (float) $sec + ((float) $usec * 100000);
  srand($seed); 
  $alfa = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
  $password = "";
  for($i = 0; $i < $length; $i ++)
  {
    $password .= $alfa[rand(0, strlen($alfa))];
  }
  
  return $password;
}

function ShowResetPassword()
{
  global $captchaType;
  $html = '<h2>Reset Password</h2><br>
          <form action="index.php" id="apform" method="POST" >
          <b>Account name</b><br>
          Please enter your account name<br>
          <input type="text" id="apinput" name="_login"><br><br>
          Please enter your email address<br>
          <input type="text" id="apinput" name="_email"><br><br>
          <input type="hidden" name="_type" value="3">
          <b>Captcha</b><br>';
          
  if($captchaType == 1)
  {
    $html .= "Please fit the image<br>";
  }else
  {
    $html .= "Please enter the code<br>";
  }
  $html .= ShowCaptcha().'<br><br>
          <input type="submit" id="apsubmit" name="_submit" value="Create">
          </form>';
          
  return $html;
}

function RequestResetPassword()
{
  $login = $_POST['_login'];
  $email = $_POST['_email'];
  
  if(!IsValidLogin($login))
  {
    echo '<div style="color: red;">Invalid account name!<br>Please try again.</div>';
    echo ShowResetPassword();
    return FALSE;
  }
  if(!IsValidEmail($email))
  {
    echo '<div style="color: red;">Invalid email!<br>Please try again.</div>';
    echo ShowResetPassword();
    return FALSE;
  }
  
  if(!IsValidCaptcha())
  {
    echo '<div style="color: red;">Captcha doesn\'t match!<br>Please try again.</div>';
    echo ShowResetPassword();
    return FALSE;
  }
  
  $accountId = DBGetAccountId($login);
  if($accountId <= 0)
  {
    echo '<div style="color: red;">Account doesn\'t exist!<br>Please try again.</div>';
    echo ShowResetPassword();
    return FALSE;
  }
  
  $newPassword = GeneratePassword();
  $accountId = DBResetPassword($login, $email, $newPassword);
  if($accountId > 0)
  {
    echo '<h2>Password has been resetted!<br>Please check your email to see details.</h2><br>';
    return TRUE;
  }else if($accountId == -1)
  {
    echo '<div style="color: red;">Email doesn\'t match!<br>Please try again.</div>';
    echo ShowResetPassword();
    return FALSE;
  }else
  {
    echo '<div style="color: red;">Database Error('.$accountId.')!<br>Please try again later.</div>';
    return FALSE;
  }
}
?>