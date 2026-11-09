<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Edit Task Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Authorization Check (IDOR Prevention): Ensures task belongs strictly
 *   to the logged-in user (WHERE id = :id AND user_id = :user_id).
 * - CSRF token verification on update submission.
 * - Input validation & sanitization on all fields.
 * - Prepared SQL UPDATE statements.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

$user_id = current_user_id();
$task_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT) 
    ?? filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);

if (!$task_id) {
    set_flash('danger', 'Invalid task identifier specified.');
    header('Location: dashboard.php');
    exit;
}

// 1. Fetch Existing Task Ensuring Strict User Ownership
try {
    $stmt = $pdo->prepare("SELECT * FROM tasks WHERE id = :id AND user_id = :user_id LIMIT 1");
    $stmt->execute([':id' => $task_id, ':user_id' => $user_id]);
    $task = $stmt->fetch();

    if (!$task) {
        // SECURITY: Prevents Insecure Direct Object Reference (IDOR).
        // Unauthorized access attempts return a generic not-found message.
        set_flash('danger', 'Task not found or you do not have permission to modify it.');
        header('Location: dashboard.php');
        exit;
    }
} catch (PDOException $e) {
    error_log("[Edit Task Fetch Error] " . $e->getMessage());
    set_flash('danger', 'An error occurred while loading task data.');
    header('Location: dashboard.php');
    exit;
}

$errors      = [];
$title       = $task['title'];
$description = $task['description'] ?? '';
$priority    = $task['priority'];
$due_date    = $task['due_date'] ?? '';
$status      = $task['status'];

// 2. Handle Update Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    validate_csrf();

    $title       = sanitize_text($_POST['title'] ?? '');
    $description = sanitize_text($_POST['description'] ?? '');
    $priority    = sanitize_text($_POST['priority'] ?? 'Medium');
    $due_date    = sanitize_text($_POST['due_date'] ?? '');
    $status      = sanitize_text($_POST['status'] ?? 'Pending');

    // Validation
    if (empty($title)) {
        $errors[] = "Task title is required.";
    } elseif (mb_strlen($title) > 255) {
        $errors[] = "Task title cannot exceed 255 characters.";
    }

    $allowed_priorities = ['Low', 'Medium', 'High'];
    if (!in_array($priority, $allowed_priorities, true)) {
        $priority = 'Medium';
    }

    $allowed_statuses = ['Pending', 'Completed'];
    if (!in_array($status, $allowed_statuses, true)) {
        $status = 'Pending';
    }

    $formatted_due_date = null;
    if (!empty($due_date)) {
        $date_obj = DateTime::createFromFormat('Y-m-d', $due_date);
        if ($date_obj && $date_obj->format('Y-m-d') === $due_date) {
            $formatted_due_date = $due_date;
        } else {
            $errors[] = "Invalid due date format. Please use YYYY-MM-DD.";
        }
    }

    // Update with Prepared Statement
    if (empty($errors)) {
        try {
            $update_stmt = $pdo->prepare("
                UPDATE tasks 
                SET title = :title, 
                    description = :description, 
                    priority = :priority, 
                    due_date = :due_date, 
                    status = :status 
                WHERE id = :id AND user_id = :user_id
            ");

            $update_stmt->execute([
                ':title'       => $title,
                ':description' => !empty($description) ? $description : null,
                ':priority'    => $priority,
                ':due_date'    => $formatted_due_date,
                ':status'      => $status,
                ':id'          => $task_id,
                ':user_id'     => $user_id,
            ]);

            set_flash('success', 'Task "' . htmlspecialchars($title) . '" updated successfully.');
            header('Location: dashboard.php');
            exit;
        } catch (PDOException $e) {
            error_log("[Edit Task Update Error] " . $e->getMessage());
            $errors[] = "An error occurred while updating the task.";
        }
    }
}

$page_title = "Edit Task";
require_once __DIR__ . '/includes/header.php';
?>

<div style="max-width: 680px; margin: 0 auto;">
    <div style="margin-bottom: 1.5rem; display: flex; align-items: center; justify-content: space-between;">
        <div>
            <h1>Edit Task</h1>
            <p>Modify task details, deadlines, and completion status.</p>
        </div>
        <a href="dashboard.php" class="btn btn-outline btn-sm">&larr; Back to Dashboard</a>
    </div>

    <div class="card">
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <div class="alert-content">
                    <ul style="margin-left: 1rem; list-style-type: disc;">
                        <?php foreach ($errors as $error): ?>
                            <li><?= e($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        <?php endif; ?>

        <form action="edit_task.php?id=<?= (int)$task_id; ?>" method="POST" novalidate>
            <?= csrf_field(); ?>
            <input type="hidden" name="task_id" value="<?= (int)$task_id; ?>">

            <div class="form-group">
                <label for="title" class="form-label">Task Title <span class="required">*</span></label>
                <input 
                    type="text" 
                    id="title" 
                    name="title" 
                    class="form-control" 
                    value="<?= e($title); ?>" 
                    required 
                    maxlength="255"
                >
            </div>

            <div class="form-group">
                <label for="description" class="form-label">Description</label>
                <textarea 
                    id="description" 
                    name="description" 
                    class="form-control" 
                    rows="4"
                ><?= e($description); ?></textarea>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label for="priority" class="form-label">Priority Level <span class="required">*</span></label>
                    <select id="priority" name="priority" class="form-control" required>
                        <option value="Low" <?= ($priority === 'Low') ? 'selected' : ''; ?>>Low</option>
                        <option value="Medium" <?= ($priority === 'Medium') ? 'selected' : ''; ?>>Medium</option>
                        <option value="High" <?= ($priority === 'High') ? 'selected' : ''; ?>>High</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="status" class="form-label">Status <span class="required">*</span></label>
                    <select id="status" name="status" class="form-control" required>
                        <option value="Pending" <?= ($status === 'Pending') ? 'selected' : ''; ?>>Pending</option>
                        <option value="Completed" <?= ($status === 'Completed') ? 'selected' : ''; ?>>Completed</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="due_date" class="form-label">Due Date</label>
                    <input 
                        type="date" 
                        id="due_date" 
                        name="due_date" 
                        class="form-control" 
                        value="<?= e($due_date); ?>"
                    >
                </div>
            </div>

            <div style="display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--slate-100);">
                <a href="dashboard.php" class="btn btn-outline">Cancel</a>
                <button type="submit" class="btn btn-teal">Save Changes</button>
            </div>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

