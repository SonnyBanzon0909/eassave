<?php

$root = $_SERVER['DOCUMENT_ROOT'];

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../config.php'; // Secure database connection

// Function to prevent direct access
function blockDirectAccess() {
    if (basename($_SERVER['PHP_SELF']) === basename(__FILE__)) {
        http_response_code(403);
        // Redirect user after logout
        header("Location: " . $root . "/eassave/404.php");
        die(json_encode(["status" => "error", "message" => "Direct access not allowed"]));
    }
}
blockDirectAccess();

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(403);
    echo json_encode(["status" => "error", "message" => "Unauthorized request"]);
    // Redirect user after logout
        header("Location: " . $root . "/eassave/404.php");
    exit;
}

// Remove remember_me cookie securely
if (isset($_COOKIE['remember_me'])) {
    setcookie('remember_me', '', time() - 3600, '/', '', true, true); // Secure flag

    // Remove token from the database
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    if ($conn->connect_error) {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Database error"]);
        exit;
    }

    $stmt = $conn->prepare("UPDATE users SET remember_token = NULL WHERE remember_token = ?");
    $stmt->bind_param("s", $_COOKIE['remember_me']);
    $stmt->execute();
    $stmt->close();
    $conn->close();
}

// Destroy session securely
$_SESSION = [];
session_unset();
session_destroy();

echo json_encode(["status" => "success", "message" => "Logged out successfully"]);
exit;
?>
