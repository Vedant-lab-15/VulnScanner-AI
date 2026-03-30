<?php
/**
 * INTENTIONALLY VULNERABLE PHP application.
 * FOR TESTING PURPOSES ONLY — DO NOT DEPLOY.
 */

// A02: Hardcoded credentials
$db_password = "admin123";
define('API_KEY', 'sk-supersecretkey');

// A05: Debug / error display
ini_set('display_errors', 'On');
error_reporting(E_ALL);

// ── A03: SQL Injection ────────────────────────────────────────────────────────
$conn = new mysqli("localhost", "root", $db_password, "app");
$id = $_GET['id'];
// VULNERABLE: user input directly in query
$result = $conn->query("SELECT * FROM users WHERE id = $id");

// ── A03: XSS ─────────────────────────────────────────────────────────────────
$name = $_GET['name'];
// VULNERABLE: echoing unsanitised user input
echo "<h1>Hello " . $name . "</h1>";

// ── A03: Command Injection ────────────────────────────────────────────────────
$host = $_GET['host'];
// VULNERABLE: user input in shell_exec
$output = shell_exec("ping -c 1 " . $host);
echo $output;

// ── A01: Path Traversal ───────────────────────────────────────────────────────
$file = $_GET['file'];
// VULNERABLE: no path sanitisation
$content = file_get_contents("/uploads/" . $file);
echo $content;

// ── A02: Weak hashing ─────────────────────────────────────────────────────────
$password = $_POST['password'];
// VULNERABLE: MD5 for password hashing
$hashed = md5($password);

// ── A01: File inclusion ───────────────────────────────────────────────────────
$page = $_GET['page'];
// VULNERABLE: remote/local file inclusion
include($page . ".php");
?>
