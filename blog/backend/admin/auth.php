<?php
// =============================================================================
// SAN Blog – Admin Auth Helper
// =============================================================================

require_once __DIR__ . '/../config.php';

session_start();

function isLoggedIn(): bool
{
    return !empty($_SESSION['san_admin_logged_in']);
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit;
    }
}

function doLogin(string $username, string $password): bool
{
    if ($username === ADMIN_USERNAME && password_verify($password, ADMIN_PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['san_admin_logged_in'] = true;
        $_SESSION['san_admin_username']  = $username;
        return true;
    }
    return false;
}

function doLogout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
}
