<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Logout Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Checks CSRF token on POST requests.
 * - Completely purges server-side session data.
 * - Explicitly expires and removes the client session cookie.
 * - Calls session_destroy() to release storage resources.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';

// If POST request, validate CSRF token
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        error_log('[Security Warning] Logout initiated with invalid CSRF token.');
    }
}

// Perform complete session revocation
logout_user();

// Start fresh session solely to deliver the logout notice
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
set_flash('success', 'You have been logged out securely.');

header('Location: login.php');
exit;

