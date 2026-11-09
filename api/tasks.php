<?php
/**
 * ====================================================================
 * Secure Task Management System
 * RESTful JSON API Endpoint (/api/tasks.php)
 * 
 * Capabilities:
 * - Scoped multi-tenant data retrieval in JSON.
 * - Authenticated session validation.
 * - HTTP status code compliance (200, 401, 405, 500).
 * ====================================================================
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/db.php';

// Only allow GET requests on read endpoint
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed. Use GET.'], JSON_PRETTY_PRINT);
    exit;
}

// 1. Authentication Guard
if (!is_logged_in()) {
    http_response_code(401);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Authentication required. Please log in first.'
    ], JSON_PRETTY_PRINT);
    exit;
}

$user_id = current_user_id();
$status_filter   = sanitize_text($_GET['status'] ?? '');
$priority_filter = sanitize_text($_GET['priority'] ?? '');

try {
    // Build query
    $sql = "SELECT id, title, description, priority, due_date, status, approval_status, admin_notes, created_at 
            FROM tasks 
            WHERE user_id = :user_id";
    $params = [':user_id' => $user_id];

    if (!empty($status_filter)) {
        $sql .= " AND status = :status";
        $params[':status'] = $status_filter;
    }

    if (!empty($priority_filter)) {
        $sql .= " AND priority = :priority";
        $params[':priority'] = $priority_filter;
    }

    $sql .= " ORDER BY created_at DESC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $tasks = $stmt->fetchAll();

    // Summary statistics
    $stat_stmt = $pdo->prepare("
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN approval_status = 'Pending' THEN 1 ELSE 0 END) AS under_review
        FROM tasks 
        WHERE user_id = :user_id
    ");
    $stat_stmt->execute([':user_id' => $user_id]);
    $stats = $stat_stmt->fetch();

    echo json_encode([
        'status' => 'success',
        'user'   => current_user(),
        'counts' => [
            'total'        => (int)($stats['total'] ?? 0),
            'pending'      => (int)($stats['pending'] ?? 0),
            'completed'    => (int)($stats['completed'] ?? 0),
            'under_review' => (int)($stats['under_review'] ?? 0),
        ],
        'data'   => $tasks,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log("[API Error] " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal database error.'], JSON_PRETTY_PRINT);
}
exit;
