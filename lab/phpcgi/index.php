<?php
// A tiny, ordinary PHP page -- the kind of thing php-cgi serves every day.
// There is nothing unsafe in this file. The vulnerability is not here; it is
// in how php-cgi itself parses the request's query string.
$name = isset($_GET['name']) ? htmlspecialchars($_GET['name']) : 'world';
echo "<h1>Hello, {$name}!</h1>\n";
echo "<p>Served by PHP " . phpversion() . " in CGI mode.</p>\n";
?>
