<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Administrator Control Panel (RBAC, Task Approvals & Audit Trail)
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Role-Based Access Control (RBAC): Enforces require_admin().
 * - Task Review & Approval Workflow (Approve / Reject user submissions).
 * - User Account Lifecycle Management (Active / Suspended status).
 * - Multi-tenant master oversight and DevSecOps Audit Log telemetry.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Strictly authorize administrator access
require_admin();

$admin_user = current_user();

// 1. Fetch System Telemetry & Metrics
try {
    // Total users
    $user_count_stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $total_users = (int)$user_count_stmt->fetchColumn();

    // Total tasks and breakdown
    $task_stats_stmt = $pdo->query("
        SELECT 
            COUNT(*) AS total_tasks,
            SUM(CASE WHEN approval_status = 'Pending' THEN 1 ELSE 0 END) AS pending_approvals,
            SUM(CASE WHEN approval_status = 'Approved' THEN 1 ELSE 0 END) AS approved_tasks,
            SUM(CASE WHEN approval_status = 'Rejected' THEN 1 ELSE 0 END) AS rejected_tasks,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks
        FROM tasks
    ");
    $system_task_stats = $task_stats_stmt->fetch();

    $system_total      = (int)($system_task_stats['total_tasks'] ?? 0);
    $pending_approvals = (int)($system_task_stats['pending_approvals'] ?? 0);
    $approved_tasks    = (int)($system_task_stats['approved_tasks'] ?? 0);
    $rejected_tasks    = (int)($system_task_stats['rejected_tasks'] ?? 0);
    $completed_tasks   = (int)($system_task_stats['completed_tasks'] ?? 0);

    // 2. Fetch Tasks Awaiting Approval (With User Details)
    $pending_tasks_stmt = $pdo->query("
        SELECT 
            t.id, t.user_id, t.title, t.description, t.priority, t.due_date, t.created_at,
            u.name AS user_name, u.email AS user_email
        FROM tasks t
        JOIN users u ON t.user_id = u.id
        WHERE t.approval_status = 'Pending'
        ORDER BY 
            CASE t.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END ASC,
            t.created_at ASC
    ");
    $pending_tasks = $pending_tasks_stmt->fetchAll();

    // 3. Fetch Registered Users with Status & Metrics
    $users_stmt = $pdo->query("
        SELECT 
            u.id, u.name, u.email, u.status, u.created_at,
            COUNT(t.id) AS task_count,
            SUM(CASE WHEN t.approval_status = 'Approved' THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) AS completed_count
        FROM users u
        LEFT JOIN tasks t ON u.id = t.user_id
        GROUP BY u.id, u.name, u.email, u.status, u.created_at
        ORDER BY u.id ASC
    ");
    $registered_users = $users_stmt->fetchAll();

    // 4. Fetch Master Tasks List (All users)
    $all_tasks_stmt = $pdo->query("
        SELECT 
            t.id, t.title, t.priority, t.due_date, t.status, t.approval_status, t.admin_notes, t.created_at,
            u.name AS user_name, u.email AS user_email
        FROM tasks t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
        LIMIT 50
    ");
    $all_tasks = $all_tasks_stmt->fetchAll();

    // 5. Fetch Security & Operational Audit Logs
    $audit_stmt = $pdo->query("
        SELECT 
            a.id, a.action, a.details, a.ip_address, a.created_at,
            u.name AS user_name, u.email AS user_email
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 25
    ");
    $audit_logs = $audit_stmt->fetchAll();

} catch (PDOException $e) {
    error_log("[Admin Query Error] " . $e->getMessage());
    $total_users = $system_total = $pending_approvals = $approved_tasks = $rejected_tasks = $completed_tasks = 0;
    $pending_tasks = $registered_users = $all_tasks = $audit_logs = [];
}

$page_title = "Admin Dashboard";
require_once __DIR__ . '/includes/header.php';
?>

<!-- Header Banner -->
<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
    <div>
        <div class="hero-pill" style="margin-bottom: 0.5rem; background: rgba(13, 148, 136, 0.1);">
            <svg width="14" height="14" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
            Administrator Control &amp; Workflow Governance
        </div>
        <h1>Administrator Dashboard</h1>
        <p>Review task submissions, manage user security privileges, and inspect DevSecOps audit telemetry.</p>
    </div>
    <div style="display: flex; gap: 0.75rem;">
        <a href="dashboard.php" class="btn btn-outline">&larr; My Personal Tasks</a>
    </div>
</div>

<!-- System Statistics Grid -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-icon stat-icon-pending" style="background: #fef3c7; color: #b45309;">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Awaiting Approval</h3>
            <div class="stat-value" style="color: #b45309;"><?= $pending_approvals; ?></div>
        </div>
    </div>

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
        <div class="stat-icon stat-icon-completed">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Approved Tasks</h3>
            <div class="stat-value"><?= $approved_tasks; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-priority">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Rejected Tasks</h3>
            <div class="stat-value" style="color: var(--danger);"><?= $rejected_tasks; ?></div>
        </div>
    </div>
</div>

<!-- ==================================================================== -->
<!-- SECTION 1: TASK APPROVAL & REVIEW QUEUE                              -->
<!-- ==================================================================== -->
<section style="margin-bottom: 2.5rem;">
    <div class="card" style="border-top: 4px solid var(--warning);">
        <div class="card-header">
            <div>
                <h2 class="card-title">Task Approval Queue (Pending Review)</h2>
                <p style="font-size: 0.875rem; color: var(--slate-500); margin-top: 0.2rem;">
                    Inspect and approve tasks submitted by users before they can proceed.
                </p>
            </div>
            <span class="badge badge-medium"><?= count($pending_tasks); ?> Pending</span>
        </div>

        <?php if (empty($pending_tasks)): ?>
            <div class="empty-state" style="padding: 2.5rem 1rem;">
                <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="color: var(--success); margin: 0 auto 0.75rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <h3>All caught up!</h3>
                <p>There are no tasks currently awaiting Administrator review.</p>
            </div>
        <?php else: ?>
            <div style="display: flex; flex-direction: column; gap: 1.25rem;">
                <?php foreach ($pending_tasks as $pt): ?>
                    <div style="background: var(--slate-50); border: 1px solid var(--slate-200); border-radius: var(--radius-md); padding: 1.25rem;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.75rem;">
                            <div>
                                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                                    <span class="badge badge-<?= strtolower($pt['priority']); ?>"><?= e($pt['priority']); ?> Priority</span>
                                    <span style="font-size: 0.825rem; color: var(--slate-500);">Submitted by: <strong><?= e($pt['user_name']); ?></strong> (<?= e($pt['user_email']); ?>)</span>
                                </div>
                                <h3 style="font-size: 1.15rem; color: var(--navy-900);"><?= e($pt['title']); ?></h3>
                            </div>
                            <div style="font-size: 0.825rem; color: var(--slate-500); text-align: right;">
                                <div>Due: <?= !empty($pt['due_date']) ? e(date('M d, Y', strtotime($pt['due_date']))) : 'No due date'; ?></div>
                                <div style="font-size: 0.75rem;">Created: <?= e(date('M d, Y H:i', strtotime($pt['created_at']))); ?></div>
                            </div>
                        </div>

                        <?php if (!empty($pt['description'])): ?>
                            <p style="font-size: 0.925rem; color: var(--slate-700); background: var(--white); padding: 0.75rem 1rem; border-radius: var(--radius-sm); border: 1px solid var(--slate-200); margin-bottom: 1rem;">
                                <?= nl2br(e($pt['description'])); ?>
                            </p>
                        <?php endif; ?>

                        <!-- Approval Actions Form -->
                        <form action="admin_actions.php" method="POST" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; border-top: 1px solid var(--slate-200); padding-top: 0.85rem;">
                            <?= csrf_field(); ?>
                            <input type="hidden" name="task_id" value="<?= (int)$pt['id']; ?>">

                            <div style="flex: 1; min-width: 260px;">
                                <input 
                                    type="text" 
                                    name="admin_notes" 
                                    class="form-control" 
                                    style="padding: 0.45rem 0.75rem; font-size: 0.85rem;" 
                                    placeholder="Optional note or feedback for user (e.g. Approved for sprint)..."
                                >
                            </div>

                            <div style="display: flex; gap: 0.5rem;">
                                <button type="submit" name="action" value="approve_task" class="btn btn-teal btn-sm" style="background: var(--success); border-color: var(--success);">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"></path></svg>
                                    Approve Task
                                </button>
                                <button type="submit" name="action" value="reject_task" class="btn btn-outline-danger btn-sm" onclick="return confirm('Are you sure you want to reject this task?');">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path></svg>
                                    Reject
                                </button>
                            </div>
                        </form>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</section>

<!-- ==================================================================== -->
<!-- SECTION 2: USER ACCOUNT GOVERNANCE & ACCESS CONTROL                  -->
<!-- ==================================================================== -->
<section style="margin-bottom: 2.5rem;">
    <div class="card">
        <div class="card-header">
            <div>
                <h2 class="card-title">User Account Administration</h2>
                <p style="font-size: 0.875rem; color: var(--slate-500); margin-top: 0.2rem;">
                    Manage active accounts and enforce account suspension for security compliance.
                </p>
            </div>
            <span class="badge badge-low"><?= count($registered_users); ?> Accounts</span>
        </div>

        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.925rem;">
                <thead>
                    <tr style="border-bottom: 2px solid var(--slate-200); color: var(--navy-800);">
                        <th style="padding: 0.75rem 1rem;">ID</th>
                        <th style="padding: 0.75rem 1rem;">User Details</th>
                        <th style="padding: 0.75rem 1rem;">Role</th>
                        <th style="padding: 0.75rem 1rem;">Account Status</th>
                        <th style="padding: 0.75rem 1rem;">Tasks (Approved/Total)</th>
                        <th style="padding: 0.75rem 1rem;">Member Since</th>
                        <th style="padding: 0.75rem 1rem; text-align: right;">Security Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($registered_users as $u): 
                        $is_admin_account = ($u['email'] === 'admin@securetask.local');
                        $is_suspended = (($u['status'] ?? 'Active') === 'Suspended');
                    ?>
                        <tr style="border-bottom: 1px solid var(--slate-100);">
                            <td style="padding: 0.85rem 1rem; font-weight: 600; color: var(--slate-500);">#<?= (int)$u['id']; ?></td>
                            <td style="padding: 0.85rem 1rem;">
                                <div style="font-weight: 700; color: var(--navy-900);"><?= e($u['name']); ?></div>
                                <div style="font-size: 0.825rem; color: var(--slate-500);"><?= e($u['email']); ?></div>
                            </td>
                            <td style="padding: 0.85rem 1rem;">
                                <?php if ($is_admin_account): ?>
                                    <span class="badge badge-high">Admin</span>
                                <?php else: ?>
                                    <span class="badge badge-low">User</span>
                                <?php endif; ?>
                            </td>
                            <td style="padding: 0.85rem 1rem;">
                                <?php if ($is_suspended): ?>
                                    <span class="badge" style="background:#fee2e2; color:#b91c1c;">Suspended</span>
                                <?php else: ?>
                                    <span class="badge" style="background:#d1fae5; color:#065f46;">Active</span>
                                <?php endif; ?>
                            </td>
                            <td style="padding: 0.85rem 1rem;">
                                <span style="font-weight: 700; color: var(--teal-600);"><?= (int)($u['approved_count'] ?? 0); ?></span>
                                <span style="color: var(--slate-400);">/</span>
                                <span><?= (int)$u['task_count']; ?></span>
                            </td>
                            <td style="padding: 0.85rem 1rem; font-size: 0.825rem; color: var(--slate-500);">
                                <?= e(date('M d, Y', strtotime($u['created_at']))); ?>
                            </td>
                            <td style="padding: 0.85rem 1rem; text-align: right;">
                                <?php if (!$is_admin_account): ?>
                                    <form action="admin_actions.php" method="POST" style="display:inline;">
                                        <?= csrf_field(); ?>
                                        <input type="hidden" name="action" value="toggle_user_status">
                                        <input type="hidden" name="user_id" value="<?= (int)$u['id']; ?>">
                                        <input type="hidden" name="status" value="<?= $is_suspended ? 'Active' : 'Suspended'; ?>">
                                        <button 
                                            type="submit" 
                                            class="btn btn-sm <?= $is_suspended ? 'btn-teal' : 'btn-outline-danger'; ?>"
                                            onclick="return confirm('Confirm <?= $is_suspended ? 'reactivating' : 'suspending'; ?> user account: <?= e($u['name']); ?>?');"
                                        >
                                            <?= $is_suspended ? 'Reactivate' : 'Suspend Account'; ?>
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <span style="font-size: 0.8rem; color: var(--slate-400); font-style: italic;">Protected</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</section>

<!-- ==================================================================== -->
<!-- SECTION 3: MASTER TASK REGISTRY (All Users)                          -->
<!-- ==================================================================== -->
<section style="margin-bottom: 2.5rem;">
    <div class="card">
        <div class="card-header">
            <div>
                <h2 class="card-title">Master Task Registry (All Users)</h2>
                <p style="font-size: 0.875rem; color: var(--slate-500); margin-top: 0.2rem;">
                    Full transparency across all submitted tasks in the system.
                </p>
            </div>
            <span class="badge badge-low"><?= count($all_tasks); ?> Records</span>
        </div>

        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem;">
                <thead>
                    <tr style="border-bottom: 2px solid var(--slate-200); color: var(--navy-800);">
                        <th style="padding: 0.75rem 1rem;">Task Title</th>
                        <th style="padding: 0.75rem 1rem;">Owner</th>
                        <th style="padding: 0.75rem 1rem;">Priority</th>
                        <th style="padding: 0.75rem 1rem;">Due Date</th>
                        <th style="padding: 0.75rem 1rem;">Approval</th>
                        <th style="padding: 0.75rem 1rem;">Progress</th>
                        <th style="padding: 0.75rem 1rem;">Admin Note</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($all_tasks as $at): ?>
                        <tr style="border-bottom: 1px solid var(--slate-100);">
                            <td style="padding: 0.8rem 1rem; font-weight: 600; color: var(--navy-900); max-width: 240px;"><?= e($at['title']); ?></td>
                            <td style="padding: 0.8rem 1rem; color: var(--slate-600);"><?= e($at['user_name']); ?></td>
                            <td style="padding: 0.8rem 1rem;">
                                <span class="badge badge-<?= strtolower($at['priority']); ?>"><?= e($at['priority']); ?></span>
                            </td>
                            <td style="padding: 0.8rem 1rem; font-size: 0.825rem;">
                                <?= !empty($at['due_date']) ? e(date('M d, Y', strtotime($at['due_date']))) : '-'; ?>
                            </td>
                            <td style="padding: 0.8rem 1rem;">
                                <?php if ($at['approval_status'] === 'Approved'): ?>
                                    <span class="badge" style="background:#ccfbf1; color:#0f766e;">Approved</span>
                                <?php elseif ($at['approval_status'] === 'Pending'): ?>
                                    <span class="badge" style="background:#fef3c7; color:#b45309;">Pending</span>
                                <?php else: ?>
                                    <span class="badge" style="background:#fee2e2; color:#b91c1c;">Rejected</span>
                                <?php endif; ?>
                            </td>
                            <td style="padding: 0.8rem 1rem;">
                                <span class="badge badge-<?= strtolower($at['status']); ?>"><?= e($at['status']); ?></span>
                            </td>
                            <td style="padding: 0.8rem 1rem; font-size: 0.825rem; color: var(--slate-500); max-width: 200px;">
                                <?= !empty($at['admin_notes']) ? e($at['admin_notes']) : '-'; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</section>

<!-- ==================================================================== -->
<!-- SECTION 4: DEVSECOPS SECURITY AUDIT TRAILS (SIEM / Event Monitoring) -->
<!-- ==================================================================== -->
<section style="margin-bottom: 2.5rem;">
    <div class="card">
        <div class="card-header">
            <div>
                <h2 class="card-title">Security &amp; Operational Audit Trail</h2>
                <p style="font-size: 0.875rem; color: var(--slate-500); margin-top: 0.2rem;">
                    OWASP A09 Logging &amp; Monitoring telemetry tracking system events, logins, and workflow changes.
                </p>
            </div>
            <span class="badge badge-completed">Live SIEM Feed</span>
        </div>

        <?php if (empty($audit_logs)): ?>
            <p style="color: var(--slate-500); padding: 1.5rem 0;">No audit entries recorded yet.</p>
        <?php else: ?>
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; font-family: var(--font-sans);">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--slate-200); color: var(--navy-800);">
                            <th style="padding: 0.65rem 0.85rem;">Timestamp</th>
                            <th style="padding: 0.65rem 0.85rem;">Action</th>
                            <th style="padding: 0.65rem 0.85rem;">Initiator</th>
                            <th style="padding: 0.65rem 0.85rem;">Details</th>
                            <th style="padding: 0.65rem 0.85rem;">IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($audit_logs as $log): ?>
                            <tr style="border-bottom: 1px solid var(--slate-100);">
                                <td style="padding: 0.65rem 0.85rem; color: var(--slate-500); font-family: monospace;">
                                    <?= e(date('Y-m-d H:i:s', strtotime($log['created_at']))); ?>
                                </td>
                                <td style="padding: 0.65rem 0.85rem;">
                                    <code style="background: var(--navy-100); padding: 0.15rem 0.4rem; border-radius: 4px; font-weight: 700; color: var(--navy-900);">
                                        <?= e($log['action']); ?>
                                    </code>
                                </td>
                                <td style="padding: 0.65rem 0.85rem; color: var(--slate-700);">
                                    <?= !empty($log['user_name']) ? e($log['user_name']) : 'System / Guest'; ?>
                                </td>
                                <td style="padding: 0.65rem 0.85rem; color: var(--slate-600);">
                                    <?= e($log['details']); ?>
                                </td>
                                <td style="padding: 0.65rem 0.85rem; color: var(--slate-500); font-family: monospace;">
                                    <?= e($log['ip_address']); ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</section>

<!-- Section 5: Telemetry Snapshot -->
<div class="card">
    <div class="card-header">
        <h2 class="card-title">Environment &amp; Infrastructure Health</h2>
        <span class="badge badge-completed">Operational</span>
    </div>

    <div class="features-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">PHP VERSION</div>
            <div style="font-weight: 700; color: var(--navy-900); margin-top: 0.25rem;">PHP <?= phpversion(); ?></div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">SECURITY GUARDS</div>
            <div style="font-weight: 700; color: var(--teal-600); margin-top: 0.25rem;">RBAC + CSRF + PDO</div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">SESSION FLAGS</div>
            <div style="font-weight: 700; color: var(--success); margin-top: 0.25rem;">HttpOnly + SameSite=Lax</div>
        </div>

        <div style="background: var(--slate-50); padding: 1rem; border-radius: var(--radius-md);">
            <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">CI/CD AUTOMATION</div>
            <div style="font-weight: 700; color: var(--navy-900); margin-top: 0.25rem;">GitHub Actions (Passing)</div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
