<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Authentication & Session Management Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Secure cookie flags (HttpOnly, SameSite=Lax, Secure condition).
 * - Strict session mode and cookie-only session IDs.
 * - Session fixation prevention via session_regenerate_id(true).
 * - Session inactivity timeout enforcement.
 * - Robust authorization guards (require_login / require_guest).
 * - Centralized XSS output escaping function e().
 * - Flash messaging system for secure status feedback.
 * ====================================================================
 */

// Configure secure session cookie parameters before starting session
if (session_status() === PHP_SESSION_NONE) {
    // Ensure session save path is writable
    $save_path = session_save_path();
    if (empty($save_path) || !is_dir($save_path) || !is_writable($save_path)) {
        @session_save_path(sys_get_temp_dir());
    }

    // Detect HTTPS status
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

    if (!headers_sent()) {
        // Apply strict security settings to session cookies
        session_set_cookie_params([
            'lifetime' => 0,               // Session lasts until browser closes
            'path'     => '/',
            'domain'   => '',              // Default host
            'secure'   => $is_https,       // True when served over HTTPS, false for local HTTP in XAMPP
            'httponly' => true,            // SECURITY: Prevents JavaScript document.cookie access (Mitigates XSS cookie theft)
            'samesite' => 'Lax'            // SECURITY: Prevents CSRF on top-level navigations
        ]);

        // Enforce strict session handling
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
    }

    @session_start();
}

// Session inactivity timeout (30 minutes = 1800 seconds)
$session_timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $session_timeout)) {
    // Invalidate stale session
    session_unset();
    session_destroy();
    session_start();
    set_flash('info', 'Your session has timed out due to inactivity. Please log in again.');
}
$_SESSION['last_activity'] = time();

/**
 * Determine if the client is currently authenticated.
 * 
 * @return bool
 */
function is_logged_in(): bool {
    return !empty($_SESSION['user_id']);
}

/**
 * Retrieve the currently authenticated user's ID.
 * 
 * @return int|null
 */
function current_user_id(): ?int {
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

/**
 * Retrieve current user profile summary from session.
 * 
 * @return array
 */
function current_user(): array {
    return [
        'id'    => current_user_id(),
        'name'  => $_SESSION['user_name'] ?? 'Guest',
        'email' => $_SESSION['user_email'] ?? '',
    ];
}

/**
 * Authorize the user: Ensures the user is logged in.
 * If not authenticated, redirects to login.php immediately.
 * 
 * @return void
 */
function require_login(): void {
    if (!is_logged_in()) {
        set_flash('danger', 'You must log in first to access that page.');
        header('Location: login.php');
        exit;
    }
}

/**
 * Check if the currently authenticated user has administrator privileges.
 * 
 * @return bool
 */
function is_admin(): bool {
    if (!is_logged_in()) {
        return false;
    }
    $user = current_user();
    return ($user['email'] === 'admin@securetask.local');
}

/**
 * Gatekeeper enforcing administrator access (Role-Based Access Control / RBAC).
 * 
 * @return void
 */
function require_admin(): void {
    require_login();
    if (!is_admin()) {
        set_flash('danger', 'Access Denied: Administrator privileges required to access that area.');
        header('Location: dashboard.php');
        exit;
    }
}

/**
 * Guest gatekeeper: Ensures authenticated users do not revisit
 * login or registration pages needlessly.
 * 
 * @return void
 */
function require_guest(): void {
    if (is_logged_in()) {
        header('Location: dashboard.php');
        exit;
    }
}

/**
 * Log in a user securely by regenerating the session identifier,
 * setting identity parameters, and resetting security tokens.
 * 
 * @param array $user Database user row containing id, name, and email.
 * @return void
 */
function login_user(array $user): void {
    // SECURITY: Regenerate session ID to prevent Session Fixation attacks
    session_regenerate_id(true);

    $_SESSION['user_id']    = (int)$user['id'];
    $_SESSION['user_name']  = (string)$user['name'];
    $_SESSION['user_email'] = (string)$user['email'];
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();

    // Reset CSRF token for the authenticated session
    unset($_SESSION['csrf_token']);
}

/**
 * Terminate the user session securely.
 * Clears session data, deletes cookie, and destroys session store.
 * 
 * @return void
 */
function logout_user(): void {
    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();
}

/**
 * Register a flash message for single-display notification.
 * 
 * @param string $type Message style: 'success', 'danger', 'warning', 'info'
 * @param string $message Descriptive message text
 * @return void
 */
function set_flash(string $type, string $message): void {
    if (!isset($_SESSION['flash_messages'])) {
        $_SESSION['flash_messages'] = [];
    }
    $_SESSION['flash_messages'][] = [
        'type'    => $type,
        'message' => $message,
    ];
}

/**
 * Retrieve and clear all stored flash messages.
 * 
 * @return array
 */
function get_flashes(): array {
    if (empty($_SESSION['flash_messages'])) {
        return [];
    }
    $flashes = $_SESSION['flash_messages'];
    unset($_SESSION['flash_messages']);
    return $flashes;
}

/**
 * SECURITY HELPER: Output Escaping (Cross-Site Scripting / XSS Prevention).
 * All user-supplied data rendered into HTML must pass through this function.
 * 
 * @param string|null $string Unescaped string
 * @return string Safe, HTML-escaped string
 */
function e(?string $string): string {
    return htmlspecialchars($string ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Sanitize text input by trimming whitespace and filtering null bytes.
 * 
 * @param string|null $input
 * @return string
 */
function sanitize_text(?string $input): string {
    if ($input === null) {
        return '';
    }
    // Remove null bytes which can disrupt file or string operations
    $clean = str_replace(chr(0), '', $input);
    return trim($clean);
}
