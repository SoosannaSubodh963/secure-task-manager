<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Administrator Workflow Controller (Approvals & Account Management)
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Strict Role-Based Access Control (RBAC): Enforces require_admin().
 * - Enforces HTTP POST verb with Synchronizer CSRF token validation.
 * - Multi-tenant security & parameter binding.
 * - Comprehensive DevSecOps Audit Logging for all administrative actions.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize administrator strictly
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    set_flash('danger', 'Invalid request method. POST required.');
    header('Location: admin.php');
    exit;
}

// 1. Verify CSRF Token
validate_csrf();

$action   = sanitize_text($_POST['action'] ?? '');
$admin_id = current_user_id();

switch ($action) {
    case 'approve_task':
        $task_id     = filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);
        $admin_notes = sanitize_text($_POST['admin_notes'] ?? 'Approved by Administrator');

        if (!$task_id) {
            set_flash('danger', 'Invalid task specified.');
            break;
        }

        try {
            $stmt = $pdo->prepare("
                UPDATE tasks 
                SET approval_status = 'Approved', 
                    admin_notes = :notes 
                WHERE id = :id
            ");
            $stmt->execute([':notes' => $admin_notes, ':id' => $task_id]);

            // DevSecOps Audit Log
            audit_log('TASK_APPROVED', "Admin approved task #{$task_id} with note: '{$admin_notes}'", $admin_id);

            set_flash('success', "Task #{$task_id} has been approved.");
        } catch (PDOException $e) {
            error_log("[Admin Action Error] " . $e->getMessage());
            set_flash('danger', 'Database error approving task.');
        }
        break;

    case 'reject_task':
        $task_id = filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);
        $reason  = sanitize_text($_POST['admin_notes'] ?? 'Task rejected by Administrator.');

        if (!$task_id) {
            set_flash('danger', 'Invalid task specified.');
            break;
        }

        try {
            $stmt = $pdo->prepare("
                UPDATE tasks 
                SET approval_status = 'Rejected', 
                    admin_notes = :notes 
                WHERE id = :id
            ");
            $stmt->execute([':notes' => $reason, ':id' => $task_id]);

            audit_log('TASK_REJECTED', "Admin rejected task #{$task_id}. Reason: '{$reason}'", $admin_id);

            set_flash('warning', "Task #{$task_id} has been rejected.");
        } catch (PDOException $e) {
            error_log("[Admin Action Error] " . $e->getMessage());
            set_flash('danger', 'Database error rejecting task.');
        }
        break;

    case 'toggle_user_status':
        $target_user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
        $new_status     = sanitize_text($_POST['status'] ?? 'Active');

        if (!$target_user_id) {
            set_flash('danger', 'Invalid user specified.');
            break;
        }

        if ($target_user_id === $admin_id) {
            set_flash('danger', 'Security Restriction: Administrators cannot suspend their own account.');
            break;
        }

        $allowed_statuses = ['Active', 'Suspended'];
        if (!in_array($new_status, $allowed_statuses, true)) {
            $new_status = 'Active';
        }

        try {
            $stmt = $pdo->prepare("UPDATE users SET status = :status WHERE id = :id");
            $stmt->execute([':status' => $new_status, ':id' => $target_user_id]);

            audit_log('USER_STATUS_CHANGE', "User #{$target_user_id} account status changed to '{$new_status}'", $admin_id);

            set_flash('info', "User #{$target_user_id} account is now {$new_status}.");
        } catch (PDOException $e) {
            error_log("[Admin Action Error] " . $e->getMessage());
            set_flash('danger', 'Error updating user status.');
        }
        break;

    default:
        set_flash('warning', 'Unknown administrative action requested.');
        break;
}

header('Location: admin.php');
exit;
