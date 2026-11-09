<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Cross-Site Request Forgery (CSRF) Protection Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Employs the Synchronizer Token Pattern (OWASP recommendation).
 * - Generates cryptographically secure, unguessable 256-bit pseudorandom tokens
 *   using PHP's random_bytes().
 * - Compares submitted tokens using hash_equals() to prevent timing-based
 *   side-channel attacks.
 * - Protects all state-changing HTTP requests (POST, PUT, DELETE).
 * ====================================================================
 */

// Ensure session is started before accessing session data
if (session_status() === PHP_SESSION_NONE) {
    $save_path = session_save_path();
    if (empty($save_path) || !is_dir($save_path) || !is_writable($save_path)) {
        @session_save_path(sys_get_temp_dir());
    }
    @session_start();
}

/**
 * Generate and store a new CSRF token in the session if not present.
 * 
 * @return string The 64-character hexadecimal CSRF token.
 */
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Retrieve the current CSRF token from session, generating one if needed.
 * 
 * @return string The CSRF token.
 */
function get_csrf_token(): string {
    return generate_csrf_token();
}

/**
 * Output an HTML hidden input element containing the current CSRF token.
 * 
 * @return string HTML hidden input string.
 */
function csrf_field(): string {
    $token = htmlspecialchars(get_csrf_token(), ENT_QUOTES, 'UTF-8');
    return '<input type="hidden" name="csrf_token" value="' . $token . '">';
}

/**
 * Verify whether a provided token matches the token stored in the session.
 * 
 * @param string|null $token The token submitted via form/headers.
 * @return bool True if valid, false otherwise.
 */
function verify_csrf_token(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Enforce CSRF token validation for incoming POST requests.
 * If invalid or missing, halts execution with an HTTP 403 Forbidden status
 * and an informative security error message.
 * 
 * @return void
 */
function validate_csrf(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!verify_csrf_token($token)) {
            error_log('[Security Warning] CSRF token validation failed for IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'));
            http_response_code(403);
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>403 Forbidden - CSRF Validation Failed</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 1rem; }
                    .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 12px; padding: 2.5rem; max-width: 500px; text-align: center; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
                    h1 { color: #f87171; font-size: 1.6rem; margin-top: 0; }
                    p { color: #cbd5e1; line-height: 1.6; font-size: 0.95rem; }
                    .btn { display: inline-block; background: #0d9488; color: #fff; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 1rem; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>Security Alert: Invalid Request (CSRF)</h1>
                    <p>The form token was missing, expired, or invalid. This security feature protects your account against Cross-Site Request Forgery attacks.</p>
                    <p>Please return to the previous page, refresh, and try submitting again.</p>
                    <a href="dashboard.php" class="btn">Return to Safety</a>
                </div>
            </body>
            </html>
            <?php
            exit;
        }
    }
}
