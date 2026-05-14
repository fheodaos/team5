<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'phpids' ) );

dvwaDatabaseConnect();

// ── IP별 로그인 시도 횟수 추적 ──
function getAttemptFile( $ip ) {
	return '/tmp/dvwa_attempts_' . md5( $ip ) . '.json';
}

function countRecentAttempts( $ip ) {
	$file = getAttemptFile( $ip );
	if ( !file_exists( $file ) ) return 0;
	$data = json_decode( file_get_contents( $file ), true ) ?: [];
	$now  = time();
	return count( array_filter( $data, function( $t ) use ( $now ) { return $now - $t < 60; } ) );
}

function recordAttempt( $ip ) {
	$file = getAttemptFile( $ip );
	$data = file_exists( $file ) ? ( json_decode( file_get_contents( $file ), true ) ?: [] ) : [];
	$now  = time();
	$data = array_values( array_filter( $data, function( $t ) use ( $now ) { return $now - $t < 60; } ) );
	$data[] = $now;
	file_put_contents( $file, json_encode( $data ) );
}

if( isset( $_POST[ 'Login' ] ) ) {
	// Anti-CSRF
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'login.php' );

	$user = $_POST[ 'username' ];
	$user = stripslashes( $user );
	$user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	$pass = $_POST[ 'password' ];
	$pass = stripslashes( $pass );
	$pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$pass = md5( $pass );

	$query = ("SELECT table_schema, table_name, create_time
				FROM information_schema.tables
				WHERE table_schema='{$_DVWA['db_database']}' AND table_name='users'
				LIMIT 1");
	$result = @mysqli_query($GLOBALS["___mysqli_ston"],  $query );
	if( mysqli_num_rows( $result ) != 1 ) {
		dvwaMessagePush( "First time using DVWA.<br />Need to run 'setup.php'." );
		dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'setup.php' );
	}

	$query  = "SELECT * FROM `users` WHERE user='$user' AND password='$pass';";
	$result = @mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '.<br />Try <a href="setup.php">installing again</a>.</pre>' );
	if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...
		dvwaMessagePush( "You have logged in as '{$user}'" );
		dvwaLogin( $user );
		dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'index.php' );
	}

	// Login failed
	recordAttempt( $_SERVER['REMOTE_ADDR'] );
	dvwaMessagePush( 'Login failed' );
	dvwaRedirect( 'login.php?error=1' );
}

$messagesHtml   = messagesPopAllToHtml();
$recentAttempts = countRecentAttempts( $_SERVER['REMOTE_ADDR'] );
$showExtraField = $recentAttempts >= 5;

Header( 'Cache-Control: no-cache, must-revalidate');
Header( 'Content-Type: text/html;charset=utf-8' );
Header( 'Expires: Tue, 23 Jun 2009 12:00:00 GMT' );

// Anti-CSRF
generateSessionToken();

$loginError = isset( $_GET['error'] ) && $_GET['error'] == '1';

echo "
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">

<html xmlns=\"http://www.w3.org/1999/xhtml\">

	<head>

		<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />

		<title>Login :: Damn Vulnerable Web Application (DVWA) v" . dvwaVersionGet() . "</title>

		<link rel=\"stylesheet\" type=\"text/css\" href=\"" . DVWA_WEB_PAGE_TO_ROOT . "dvwa/css/login.css\" />

	</head>

	<body>

	" . ( $loginError ? '<script>alert(\'아이디, 비밀번호를 확인해주세요\');</script>' : '' ) . "

	<div id=\"wrapper\">

	<div id=\"header\">

	<br />

	<p><img src=\"" . DVWA_WEB_PAGE_TO_ROOT . "dvwa/images/login_logo.png\" /></p>

	<br />

	</div> <!--<div id=\"header\">-->

	<div id=\"content\">

	<form action=\"login.php\" method=\"post\">

	<fieldset>

			<label for=\"user\">Username</label> <input type=\"text\" class=\"loginInput\" size=\"20\" name=\"username\"><br />

			<label for=\"pass\">Password</label> <input type=\"password\" class=\"loginInput\" AUTOCOMPLETE=\"off\" size=\"20\" name=\"password\"><br />

			" . ( $showExtraField ? '
			<br />
			<label for=\"extra\">추가 인증</label> <input type=\"text\" class=\"loginInput\" size=\"20\" name=\"extra_auth\" placeholder=\"추가 인증 코드를 입력하세요\"><br />
			' : '' ) . "

			<br />

			<p class=\"submit\"><input type=\"submit\" value=\"Login\" name=\"Login\"></p>

	</fieldset>

	" . tokenField() . "

	</form>

	<br />

	{$messagesHtml}

	<br />
	<br />
	<br />
	<br />
	<br />
	<br />
	<br />
	<br />

	<!-- <img src=\"" . DVWA_WEB_PAGE_TO_ROOT . "dvwa/images/RandomStorm.png\" /> -->
	</div > <!--<div id=\"content\">-->

	<div id=\"footer\">

	<p>" . dvwaExternalLinkUrlGet( 'http://www.dvwa.co.uk/', 'Damn Vulnerable Web Application (DVWA)' ) . "</p>

	</div> <!--<div id=\"footer\"> -->

	</div> <!--<div id=\"wrapper\"> -->

	</body>

</html>";

?>
