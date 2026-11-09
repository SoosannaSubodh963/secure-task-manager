<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Delete Task Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Authorization Check (IDOR Prevention): Only allows deletion if
 *   user_id matches the authenticated user.
 * - HTTP Method Restriction: Strictly rejects GET requests to prevent
 *   CSRF via malicious link pre-fetching or <img> tags.
 * - CSRF Token Verification on every execution.
 * - Prepared SQL DELETE statement.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

// SECURITY: Enforce POST method only (Reject GET/HEAD/PUT etc.)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    set_flash('danger', 'Invalid request method. Task deletion requires a POST request.');
    header('Location: dashboard.php');
    exit;
}

// 1. Verify CSRF Token
validate_csrf();

// 2. Retrieve & Validate Task Identifier
$task_id = filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);
$user_id = current_user_id();

if (!$task_id) {
    set_flash('danger', 'Invalid task identifier provided.');
    header('Location: dashboard.php');
    exit;
}

// 3. Delete Task Ensuring Strict Ownership
try {
    $stmt = $pdo->prepare("DELETE FROM tasks WHERE id = :id AND user_id = :user_id");
    $stmt->execute([':id' => $task_id, ':user_id' => $user_id]);

    if ($stmt->rowCount() > 0) {
        set_flash('success', 'Task deleted successfully.');
    } else {
        // Either task doesn't exist or belongs to another user
        set_flash('danger', 'Task not found or you do not have permission to delete it.');
    }
} catch (PDOException $e) {
    error_log("[Delete Task Error] " . $e->getMessage());
    set_flash('danger', 'An error occurred while attempting to delete the task.');
}

header('Location: dashboard.php');
exit;
