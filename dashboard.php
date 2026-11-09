<?php
/**
 * ====================================================================
 * Secure Task Management System
 * User Dashboard
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Strict authentication guard (require_login).
 * - Multi-tenant isolation: All queries enforce WHERE user_id = :user_id.
 * - Output escaping: e() applied to all dynamic data (XSS mitigation).
 * - Synchronizer CSRF tokens embedded in all status and delete forms.
 * - Input validation on filter query parameters.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

$user_id   = current_user_id();
$user_info = current_user();

// 1. Fetch Summary Statistics (Strictly scoped to current user)
try {
    $stats_stmt = $pdo->prepare("
        SELECT 
            COUNT(*) AS total_tasks,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending_tasks,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks,
            SUM(CASE WHEN priority = 'High' AND status = 'Pending' THEN 1 ELSE 0 END) AS high_priority_tasks
        FROM tasks 
        WHERE user_id = :user_id
    ");
    $stats_stmt->execute([':user_id' => $user_id]);
    $stats = $stats_stmt->fetch();

    $total_count     = (int)($stats['total_tasks'] ?? 0);
    $pending_count   = (int)($stats['pending_tasks'] ?? 0);
    $completed_count = (int)($stats['completed_tasks'] ?? 0);
    $high_count      = (int)($stats['high_priority_tasks'] ?? 0);
} catch (PDOException $e) {
    error_log("[Dashboard Stats Error] " . $e->getMessage());
    $total_count = $pending_count = $completed_count = $high_count = 0;
}

// 2. Determine Filter Selection
$allowed_filters = ['all', 'pending', 'completed', 'high'];
$current_filter  = sanitize_text($_GET['filter'] ?? 'all');
if (!in_array($current_filter, $allowed_filters, true)) {
    $current_filter = 'all';
}

$search_query = sanitize_text($_GET['q'] ?? '');

// 3. Fetch Tasks with Prepared Statement
try {
    $sql = "SELECT id, title, description, priority, due_date, status, created_at 
            FROM tasks 
            WHERE user_id = :user_id";
    $params = [':user_id' => $user_id];

    if ($current_filter === 'pending') {
        $sql .= " AND status = 'Pending'";
    } elseif ($current_filter === 'completed') {
        $sql .= " AND status = 'Completed'";
    } elseif ($current_filter === 'high') {
        $sql .= " AND priority = 'High'";
    }

    if (!empty($search_query)) {
        $sql .= " AND (title LIKE :search OR description LIKE :search)";
        $params[':search'] = '%' . $search_query . '%';
    }

    // Sort order: Pending first, then priority (High -> Medium -> Low), then due date
    $sql .= " ORDER BY 
                CASE WHEN status = 'Pending' THEN 0 ELSE 1 END ASC,
                CASE priority 
                    WHEN 'High' THEN 1 
                    WHEN 'Medium' THEN 2 
                    WHEN 'Low' THEN 3 
                    ELSE 4 
                END ASC,
                due_date IS NULL ASC,
                due_date ASC,
                created_at DESC";

    $tasks_stmt = $pdo->prepare($sql);
    $tasks_stmt->execute($params);
    $tasks = $tasks_stmt->fetchAll();
} catch (PDOException $e) {
    error_log("[Dashboard Tasks Query Error] " . $e->getMessage());
    $tasks = [];
}

$page_title = "Dashboard";
require_once __DIR__ . '/includes/header.php';
?>

<!-- Welcome Banner -->
<div class="dashboard-header">
    <div>
        <h1>Welcome, <?= e($user_info['name']); ?>!</h1>
        <p>Review your priorities, track progress, and manage personal tasks securely.</p>
    </div>
    <div class="dashboard-actions">
        <button type="button" class="btn btn-teal" data-modal-target="quickAddTaskModal">
            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"></path></svg>
            Quick Add Task
        </button>
        <a href="add_task.php" class="btn btn-outline" style="border-color: rgba(255,255,255,0.3); color: #fff;">
            Full Form
        </a>
    </div>
</div>

<!-- Metrics & Statistics Grid -->
<section class="stats-grid" aria-label="Task Statistics">
    <div class="stat-card">
        <div class="stat-icon stat-icon-total">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Total Tasks</h3>
            <div class="stat-value"><?= $total_count; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-pending">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Pending Tasks</h3>
            <div class="stat-value"><?= $pending_count; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-completed">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>Completed Tasks</h3>
            <div class="stat-value"><?= $completed_count; ?></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-icon stat-icon-priority">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
        </div>
        <div class="stat-info">
            <h3>High Priority (Active)</h3>
            <div class="stat-value"><?= $high_count; ?></div>
        </div>
    </div>
</section>

<!-- Filter Toolbar -->
<div class="toolbar">
    <div class="filter-tabs">
        <a href="dashboard.php?filter=all<?= !empty($search_query) ? '&q=' . urlencode($search_query) : ''; ?>" 
           class="filter-tab <?= ($current_filter === 'all') ? 'active' : ''; ?>">
            All Tasks <span class="count"><?= $total_count; ?></span>
        </a>
        <a href="dashboard.php?filter=pending<?= !empty($search_query) ? '&q=' . urlencode($search_query) : ''; ?>" 
           class="filter-tab <?= ($current_filter === 'pending') ? 'active' : ''; ?>">
            Pending <span class="count"><?= $pending_count; ?></span>
        </a>
        <a href="dashboard.php?filter=completed<?= !empty($search_query) ? '&q=' . urlencode($search_query) : ''; ?>" 
           class="filter-tab <?= ($current_filter === 'completed') ? 'active' : ''; ?>">
            Completed <span class="count"><?= $completed_count; ?></span>
        </a>
        <a href="dashboard.php?filter=high<?= !empty($search_query) ? '&q=' . urlencode($search_query) : ''; ?>" 
           class="filter-tab <?= ($current_filter === 'high') ? 'active' : ''; ?>">
            High Priority
        </a>
    </div>

    <!-- Search Form -->
    <form action="dashboard.php" method="GET" style="display: flex; gap: 0.5rem; align-items: center;">
        <input type="hidden" name="filter" value="<?= e($current_filter); ?>">
        <input 
            type="text" 
            name="q" 
            class="form-control" 
            style="padding: 0.4rem 0.75rem; font-size: 0.875rem; width: 200px;" 
            placeholder="Search tasks..." 
            value="<?= e($search_query); ?>"
        >
        <button type="submit" class="btn btn-outline btn-sm">Filter</button>
        <?php if (!empty($search_query)): ?>
            <a href="dashboard.php?filter=<?= e($current_filter); ?>" class="btn btn-outline btn-sm" title="Clear search">&times;</a>
        <?php endif; ?>
    </form>
</div>

<!-- Task Cards Grid -->
<?php if (empty($tasks)): ?>
    <div class="empty-state">
        <svg class="empty-icon" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path></svg>
        <h3>No tasks found</h3>
        <p>
            <?php if (!empty($search_query) || $current_filter !== 'all'): ?>
                No tasks match your active filter criteria. Try resetting the filter or search query.
            <?php else: ?>
                You don't have any tasks registered yet. Add your first task to start organizing your projects!
            <?php endif; ?>
        </p>
        <button type="button" class="btn btn-teal" data-modal-target="quickAddTaskModal">
            Create Your First Task
        </button>
    </div>
<?php else: ?>
    <div class="tasks-grid">
        <?php foreach ($tasks as $task): 
            $is_completed = ($task['status'] === 'Completed');
            $priority_class = 'priority-' . strtolower($task['priority']);
            
            // Check overdue condition
            $is_overdue = false;
            if (!$is_completed && !empty($task['due_date'])) {
                $today = date('Y-m-d');
                if ($task['due_date'] < $today) {
                    $is_overdue = true;
                }
            }
        ?>
            <article class="task-card <?= $priority_class; ?> <?= $is_completed ? 'is-completed' : ''; ?>">
                <div>
                    <div class="task-meta-top">
                        <span class="badge badge-<?= strtolower($task['priority']); ?>">
                            <?= e($task['priority']); ?> Priority
                        </span>
                        <span class="badge badge-<?= strtolower($task['status']); ?>">
                            <?= e($task['status']); ?>
                        </span>
                    </div>

                    <h2 class="task-title"><?= e($task['title']); ?></h2>

                    <?php if (!empty($task['description'])): ?>
                        <p class="task-desc"><?= nl2br(e($task['description'])); ?></p>
                    <?php endif; ?>
                </div>

                <div>
                    <div class="task-footer">
                        <div class="task-due <?= $is_overdue ? 'overdue' : ''; ?>">
                            <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                            <?php if (!empty($task['due_date'])): ?>
                                <span>Due: <?= e(date('M d, Y', strtotime($task['due_date']))); ?><?= $is_overdue ? ' (Overdue!)' : ''; ?></span>
                            <?php else: ?>
                                <span>No due date</span>
                            <?php endif; ?>
                        </div>

                        <div class="task-actions">
                            <!-- Toggle Status Form (POST + CSRF) -->
                            <form action="update_status.php" method="POST" style="display:inline;">
                                <?= csrf_field(); ?>
                                <input type="hidden" name="task_id" value="<?= (int)$task['id']; ?>">
                                <input type="hidden" name="status" value="<?= $is_completed ? 'Pending' : 'Completed'; ?>">
                                <button 
                                    type="submit" 
                                    class="btn btn-outline btn-sm" 
                                    title="<?= $is_completed ? 'Mark as Pending' : 'Mark as Completed'; ?>"
                                    style="<?= $is_completed ? 'color: var(--warning);' : 'color: var(--success);'; ?>"
                                >
                                    <?= $is_completed ? 'Undo' : 'Done'; ?>
                                </button>
                            </form>

                            <!-- Edit Link -->
                            <a href="edit_task.php?id=<?= (int)$task['id']; ?>" class="btn btn-outline btn-sm" title="Edit Task">
                                Edit
                            </a>

                            <!-- Delete Trigger (Protected with Modal & CSRF) -->
                            <button 
                                type="button" 
                                class="btn btn-outline-danger btn-sm btn-delete-task" 
                                data-task-id="<?= (int)$task['id']; ?>"
                                data-task-title="<?= e($task['title']); ?>"
                                title="Delete Task"
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<!-- Quick Add Task Modal -->
<div class="modal-overlay" id="quickAddTaskModal" role="dialog" aria-modal="true" aria-labelledby="quickAddTitle">
    <div class="modal-box">
        <div class="modal-header">
            <h3 id="quickAddTitle" class="card-title">Create New Task</h3>
            <button type="button" class="alert-close" data-modal-close aria-label="Close modal">&times;</button>
        </div>

        <form action="add_task.php" method="POST">
            <div class="modal-body">
                <?= csrf_field(); ?>

                <div class="form-group">
                    <label for="modal_title" class="form-label">Task Title <span class="required">*</span></label>
                    <input 
                        type="text" 
                        id="modal_title" 
                        name="title" 
                        class="form-control" 
                        placeholder="e.g. Audit API authentication endpoints" 
                        required 
                        maxlength="255"
                    >
                </div>

                <div class="form-group">
                    <label for="modal_description" class="form-label">Description</label>
                    <textarea 
                        id="modal_description" 
                        name="description" 
                        class="form-control" 
                        placeholder="Add additional context, acceptance criteria or links..."
                        rows="3"
                    ></textarea>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="modal_priority" class="form-label">Priority <span class="required">*</span></label>
                        <select id="modal_priority" name="priority" class="form-control" required>
                            <option value="Low">Low</option>
                            <option value="Medium" selected>Medium</option>
                            <option value="High">High</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="modal_due_date" class="form-label">Due Date</label>
                        <input type="date" id="modal_due_date" name="due_date" class="form-control">
                    </div>
                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn btn-outline" data-modal-close>Cancel</button>
                <button type="submit" class="btn btn-teal">Save Task</button>
            </div>
        </form>
    </div>
</div>

<!-- Delete Confirmation Modal (CSRF Protected) -->
<div class="modal-overlay" id="deleteConfirmModal" role="dialog" aria-modal="true" aria-labelledby="deleteModalTitle">
    <div class="modal-box">
        <div class="modal-header">
            <h3 id="deleteModalTitle" class="card-title" style="color: var(--danger);">Confirm Task Deletion</h3>
            <button type="button" class="alert-close" data-modal-close aria-label="Close modal">&times;</button>
        </div>

        <form action="delete_task.php" method="POST" id="deleteTaskForm">
            <?= csrf_field(); ?>
            <input type="hidden" name="task_id" id="deleteTaskId" value="">

            <div class="modal-body">
                <p>Are you sure you want to delete the following task? This action cannot be reversed.</p>
                <div style="background-color: var(--slate-100); padding: 0.85rem; border-radius: var(--radius-sm); margin-top: 0.85rem; font-weight: 600; color: var(--navy-900);">
                    <span id="deleteTaskTitle"></span>
                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn btn-outline" data-modal-close>Cancel</button>
                <button type="submit" class="btn btn-primary" style="background-color: var(--danger);">Delete Task</button>
            </div>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
