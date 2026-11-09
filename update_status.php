<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Toggle Task Status Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Authorization Check (IDOR Prevention): Scoped strictly to logged-in user.
 * - HTTP Method Restriction: Rejects non-POST requests.
 * - CSRF Token Verification.
 * - Input validation: Whitelist checks for valid status values ('Pending', 'Completed').
 * - Prepared SQL UPDATE statement.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

// Enforce POST method only
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    set_flash('danger', 'Invalid request method. Status update requires a POST request.');
    header('Location: dashboard.php');
    exit;
}

// 1. Verify CSRF Token
validate_csrf();

// 2. Retrieve & Validate Inputs
$task_id    = filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);
$raw_status = sanitize_text($_POST['status'] ?? '');
$user_id    = current_user_id();

$allowed_statuses = ['Pending', 'Completed'];
if (!$task_id || !in_array($raw_status, $allowed_statuses, true)) {
    set_flash('danger', 'Invalid status update parameters supplied.');
    header('Location: dashboard.php');
    exit;
}

// 3. Update Status Ensuring Strict Ownership
try {
    $stmt = $pdo->prepare("
        UPDATE tasks 
        SET status = :status 
        WHERE id = :id AND user_id = :user_id
    ");
    $stmt->execute([
        ':status'  => $raw_status,
        ':id'      => $task_id,
        ':user_id' => $user_id,
    ]);

    if ($stmt->rowCount() > 0) {
        set_flash('success', 'Task status updated to "' . htmlspecialchars($raw_status) . '".');
    } else {
        set_flash('info', 'Task status was not changed.');
    }
} catch (PDOException $e) {
    error_log("[Update Status Error] " . $e->getMessage());
    set_flash('danger', 'An error occurred while updating task status.');
}

header('Location: dashboard.php');
exit;

