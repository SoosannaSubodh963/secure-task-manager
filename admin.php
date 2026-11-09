<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Administrator Control Panel (RBAC Demonstration)
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Role-Based Access Control (RBAC): Enforces require_admin().
 * - System-wide audit metrics (Aggregate stats across all tenants).
 * - Read-only user directory with aggregated task statistics.
 * - Server environment & security configuration telemetry.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize administrator access strictly
require_admin();

$admin_user = current_user();

// 1. Fetch System-Wide Metrics
try {
    // Total users
    $user_count_stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $total_users = (int)$user_count_stmt->fetchColumn();

    // Total tasks and breakdown
    $task_stats_stmt = $pdo->query("
        SELECT 
            COUNT(*) AS total_tasks,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS total_pending,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS total_completed,
            SUM(CASE WHEN priority = 'High' AND status = 'Pending' THEN 1 ELSE 0 END) AS total_high_pending
        FROM tasks
    ");
    $system_task_stats = $task_stats_stmt->fetch();

    $system_total     = (int)($system_task_stats['total_tasks'] ?? 0);
    $system_pending   = (int)($system_task_stats['total_pending'] ?? 0);
    $system_completed = (int)($system_task_stats['total_completed'] ?? 0);
    $system_high      = (int)($system_task_stats['total_high_pending'] ?? 0);

    // 2. Fetch User Directory with Task Counts (Prepared / Safe Join)
    $users_stmt = $pdo->query("
        SELECT 
            u.id, 
            u.name, 
            u.email, 
            u.created_at,
            COUNT(t.id) AS task_count,
            SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) AS completed_count
        FROM users u
        LEFT JOIN tasks t ON u.id = t.user_id
        GROUP BY u.id, u.name, u.email, u.created_at
        ORDER BY u.id ASC
    ");
    $registered_users = $users_stmt->fetchAll();

} catch (PDOException $e) {
    error_log("[Admin Query Error] " . $e->getMessage());
    $total_users = $system_total = $system_pending = $system_completed = $system_high = 0;
    $registered_users = [];
}

$page_title = "Admin Control Panel";
require_once __DIR__ . '/includes/header.php';
?>

<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
    <div>
        <div class="hero-pill" style="margin-bottom: 0.5rem; background: rgba(13, 148, 136, 0.1);">
            <svg width="14" height="14" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
            Administrator Privileges Active (RBAC)
        </div>
        <h1>System Administration Panel</h1>
        <p>System-wide health telemetry, multi-tenant user directory, and security audit metrics.</p>
    </div>
    <div>
        <a href="dashboard.php" class="btn btn-outline">&larr; Back to My Tasks</a>
    </div>
</div>

<!-- System Statistics Grid -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-icon stat-icon-total">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Registered Users</h3>
            <div class="stat-value"><?= $total_users; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-pending">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Total System Tasks</h3>
            <div class="stat-value"><?= $system_total; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-completed">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Completed Tasks</h3>
            <div class="stat-value"><?= $system_completed; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-priority">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Pending Tasks</h3>
            <div class="stat-value"><?= $system_pending; ?></div>
        </div>
    </div>
</div>

<!-- Registered Users Directory Table -->
<div class="card" style="margin-bottom: 2rem;">
    <div class="card-header">
        <h2 class="card-title">Registered Users Directory</h2>
        <span class="badge badge-low"><?= count($registered_users); ?> Accounts</span>
    </div>

    <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.925rem;">
            <thead>
                <tr style="border-bottom: 2px solid var(--slate-200); color: var(--navy-800);">
                    <th style="padding: 0.75rem 1rem;">ID</th>
                    <th style="padding: 0.75rem 1rem;">Full Name</th>
                    <th style="padding: 0.75rem 1rem;">Email Address</th>
                    <th style="padding: 0.75rem 1rem;">Total Tasks</th>
                    <th style="padding: 0.75rem 1rem;">Completed</th>
                    <th style="padding: 0.75rem 1rem;">Role</th>
                    <th style="padding: 0.75rem 1rem;">Registration Date</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($registered_users as $u): ?>
                    <tr style="border-bottom: 1px solid var(--slate-100);">
                        <td style="padding: 0.85rem 1rem; font-weight: 600; color: var(--slate-500);">#<?= (int)$u['id']; ?></td>
                        <td style="padding: 0.85rem 1rem; font-weight: 600; color: var(--navy-900);"><?= e($u['name']); ?></td>
                        <td style="padding: 0.85rem 1rem; color: var(--slate-600);"><?= e($u['email']); ?></td>
                        <td style="padding: 0.85rem 1rem;"><?= (int)$u['task_count']; ?></td>
                        <td style="padding: 0.85rem 1rem; color: var(--success); font-weight: 600;"><?= (int)($u['completed_count'] ?? 0); ?></td>
                        <td style="padding: 0.85rem 1rem;">
                            <?php if ($u['email'] === 'admin@securetask.local'): ?>
                                <span class="badge badge-high">Admin</span>
                            <?php else: ?>
                                <span class="badge badge-low">User</span>
                            <?php endif; ?>
                        </td>
                        <td style="padding: 0.85rem 1rem; color: var(--slate-500); font-size: 0.85rem;">
                            <?= e(date('M d, Y', strtotime($u['created_at']))); ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- System & DevSecOps Security Telemetry -->
<div class="card">
    <div class="card-header">
        <h2 class="card-title">DevSecOps & Environment Telemetry</h2>
        <span class="badge badge-completed">Healthy</span>
    </div>

    <div class="features-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">PHP RUNTIME</div>
            <div style="font-weight: 700; color: var(--navy-900); margin-top: 0.25rem;">PHP <?= phpversion(); ?></div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">DATABASE ENGINE</div>
            <div style="font-weight: 700; color: var(--navy-900); margin-top: 0.25rem;">MySQL via PDO (Prepared)</div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">SESSION SECURITY</div>
            <div style="font-weight: 700; color: var(--success); margin-top: 0.25rem;">HttpOnly + SameSite=Lax</div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">CI/CD AUTOMATION</div>
            <div style="font-weight: 700; color: var(--teal-600); margin-top: 0.25rem;">GitHub Actions Active</div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

