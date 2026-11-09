<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Secure Task Data Export Module (CSV / JSON)
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Strict authentication guard (require_login).
 * - Multi-tenant isolation: Only exports tasks where user_id = :user_id.
 * - Anti-CSV Injection: Prepends single quotes to cells starting with
 *   dangerous spreadsheet execution prefixes (=, +, -, @, \t, \r).
 * - DevSecOps Audit Logging of data export events.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

$user_id = current_user_id();
$format  = strtolower(sanitize_text($_GET['format'] ?? 'csv'));

try {
    $stmt = $pdo->prepare("
        SELECT id, title, description, priority, due_date, status, approval_status, admin_notes, created_at
        FROM tasks
        WHERE user_id = :user_id
        ORDER BY created_at DESC
    ");
    $stmt->execute([':user_id' => $user_id]);
    $tasks = $stmt->fetchAll();

    audit_log('TASKS_EXPORTED', "User #{$user_id} exported " . count($tasks) . " tasks in {$format} format", $user_id);

} catch (PDOException $e) {
    error_log("[Export Error] " . $e->getMessage());
    set_flash('danger', 'Error exporting tasks.');
    header('Location: dashboard.php');
    exit;
}

$filename = 'tasks-export-' . date('Y-m-d');

// 1. Export as JSON
if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '.json"');
    echo json_encode([
        'export_date' => date('Y-m-d H:i:s'),
        'user_id'     => $user_id,
        'total_tasks' => count($tasks),
        'tasks'       => $tasks,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// 2. Export as CSV (Default)
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '.csv"');
header('Pragma: no-cache');
header('Expires: 0');

$output = fopen('php://output', 'w');

// CSV Headers
fputcsv($output, [
    'Task ID',
    'Title',
    'Description',
    'Priority',
    'Due Date',
    'Progress Status',
    'Approval Status',
    'Admin Notes',
    'Created At'
]);

// Anti-CSV Formula Injection Helper
function sanitize_csv_field(?string $val): string {
    if ($val === null) return '';
    $val = (string)$val;
    // If field starts with formula trigger characters, neutralize it
    if (preg_match('/^[=\+\-@\t\r]/', $val)) {
        return "'" . $val;
    }
    return $val;
}

foreach ($tasks as $row) {
    fputcsv($output, [
        $row['id'],
        sanitize_csv_field($row['title']),
        sanitize_csv_field($row['description']),
        $row['priority'],
        $row['due_date'] ?? 'N/A',
        $row['status'],
        $row['approval_status'] ?? 'Approved',
        sanitize_csv_field($row['admin_notes']),
        $row['created_at'],
    ]);
}

fclose($output);
exit;
