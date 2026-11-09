<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Create Task Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Authorization guard (require_login).
 * - Multi-tenant security: Assigns current authenticated user's ID.
 * - CSRF token verification.
 * - Strict input validation (Priority enum check, date validation, length constraints).
 * - Prepared SQL INSERT statements.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

$errors      = [];
$title       = '';
$description = '';
$priority    = 'Medium';
$due_date    = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Verify CSRF Token
    validate_csrf();

    // 2. Sanitize & Retrieve Inputs
    $title       = sanitize_text($_POST['title'] ?? '');
    $description = sanitize_text($_POST['description'] ?? '');
    $priority    = sanitize_text($_POST['priority'] ?? 'Medium');
    $due_date    = sanitize_text($_POST['due_date'] ?? '');

    // 3. Validation Rules
    if (empty($title)) {
        $errors[] = "Task title is required.";
    } elseif (mb_strlen($title) > 255) {
        $errors[] = "Task title cannot exceed 255 characters.";
    }

    $allowed_priorities = ['Low', 'Medium', 'High'];
    if (!in_array($priority, $allowed_priorities, true)) {
        $priority = 'Medium';
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

    // 4. Insert Task with Prepared Statement
    if (empty($errors)) {
        try {
            $user_id = current_user_id();

            $stmt = $pdo->prepare("
                INSERT INTO tasks (user_id, title, description, priority, due_date, status)
                VALUES (:user_id, :title, :description, :priority, :due_date, 'Pending')
            ");

            $stmt->execute([
                ':user_id'     => $user_id,
                ':title'       => $title,
                ':description' => !empty($description) ? $description : null,
                ':priority'    => $priority,
                ':due_date'    => $formatted_due_date,
            ]);

            set_flash('success', 'Task "' . htmlspecialchars($title) . '" created successfully.');
            header('Location: dashboard.php');
            exit;
        } catch (PDOException $e) {
            error_log("[Add Task Error] " . $e->getMessage());
            $errors[] = "A database error occurred while creating the task. Please try again.";
        }
    }
}

$page_title = "Add Task";
require_once __DIR__ . '/includes/header.php';
?>

<div style="max-width: 680px; margin: 0 auto;">
    <div style="margin-bottom: 1.5rem; display: flex; align-items: center; justify-content: space-between;">
        <div>
            <h1>Create New Task</h1>
            <p>Add a new item to your personal schedule.</p>
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

        <form action="add_task.php" method="POST" novalidate>
            <?= csrf_field(); ?>

            <div class="form-group">
                <label for="title" class="form-label">Task Title <span class="required">*</span></label>
                <input 
                    type="text" 
                    id="title" 
                    name="title" 
                    class="form-control" 
                    placeholder="e.g. Conduct automated penetration testing" 
                    value="<?= e($title); ?>" 
                    required 
                    maxlength="255"
                    autofocus
                >
            </div>

            <div class="form-group">
                <label for="description" class="form-label">Description</label>
                <textarea 
                    id="description" 
                    name="description" 
                    class="form-control" 
                    placeholder="Provide details, scope, or requirements..." 
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
                <button type="submit" class="btn btn-teal">Create Task</button>
            </div>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
