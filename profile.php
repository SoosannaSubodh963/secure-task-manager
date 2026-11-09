<?php
/**
 * ====================================================================
 * Secure Task Management System
 * User Profile & Account Security Management Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Strict authentication guard (require_login).
 * - Password change requiring verification of existing password.
 * - Server-side validation of password complexity and confirmation.
 * - Bcrypt cryptographic hashing for new passwords.
 * - CSRF token verification on all profile mutations.
 * - DevSecOps Audit Logging for security credential updates.
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Authorize access
require_login();

$user_id   = current_user_id();
$user_info = current_user();

// Fetch fresh user record from database
try {
    $stmt = $pdo->prepare("SELECT id, name, email, status, created_at FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $user_id]);
    $db_user = $stmt->fetch();

    if (!$db_user) {
        logout_user();
        header('Location: login.php');
        exit;
    }

    // Task counts for user
    $t_stmt = $pdo->prepare("
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN approval_status = 'Approved' THEN 1 ELSE 0 END) AS approved
        FROM tasks 
        WHERE user_id = :id
    ");
    $t_stmt->execute([':id' => $user_id]);
    $task_stats = $t_stmt->fetch();

} catch (PDOException $e) {
    error_log("[Profile Fetch Error] " . $e->getMessage());
    $db_user = ['id' => $user_id, 'name' => 'User', 'email' => '', 'status' => 'Active', 'created_at' => date('Y-m-d')];
    $task_stats = ['total' => 0, 'completed' => 0, 'approved' => 0];
}

$profile_errors  = [];
$password_errors = [];

// Handle POST submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf();
    $action = sanitize_text($_POST['action'] ?? '');

    // 1. Update Profile Information (Name)
    if ($action === 'update_profile') {
        $new_name = sanitize_text($_POST['name'] ?? '');

        if (empty($new_name)) {
            $profile_errors[] = "Full name cannot be blank.";
        } elseif (mb_strlen($new_name) < 2 || mb_strlen($new_name) > 100) {
            $profile_errors[] = "Full name must be between 2 and 100 characters.";
        }

        if (empty($profile_errors)) {
            try {
                $u_stmt = $pdo->prepare("UPDATE users SET name = :name WHERE id = :id");
                $u_stmt->execute([':name' => $new_name, ':id' => $user_id]);

                // Update session
                $_SESSION['user_name'] = $new_name;
                $db_user['name'] = $new_name;

                audit_log('PROFILE_NAME_UPDATED', "User #{$user_id} updated name to '{$new_name}'", $user_id);
                set_flash('success', 'Profile name updated successfully.');
                header('Location: profile.php');
                exit;
            } catch (PDOException $e) {
                error_log("[Profile Update Error] " . $e->getMessage());
                $profile_errors[] = "Failed to update profile. Please try again.";
            }
        }
    }

    // 2. Change Password
    if ($action === 'change_password') {
        $current_pwd = $_POST['current_password'] ?? '';
        $new_pwd     = $_POST['new_password'] ?? '';
        $confirm_pwd = $_POST['confirm_password'] ?? '';

        if (empty($current_pwd)) {
            $password_errors[] = "Current password is required.";
        }

        if (empty($new_pwd)) {
            $password_errors[] = "New password is required.";
        } elseif (strlen($new_pwd) < 8) {
            $password_errors[] = "New password must be at least 8 characters long.";
        } elseif (!preg_match('/[A-Za-z]/', $new_pwd) || !preg_match('/[0-9]/', $new_pwd)) {
            $password_errors[] = "New password must include both letters and numbers.";
        }

        if ($new_pwd !== $confirm_pwd) {
            $password_errors[] = "New password confirmation does not match.";
        }

        // Verify existing password
        if (empty($password_errors)) {
            try {
                $p_stmt = $pdo->prepare("SELECT password FROM users WHERE id = :id LIMIT 1");
                $p_stmt->execute([':id' => $user_id]);
                $hash = $p_stmt->fetchColumn();

                if (!$hash || !password_verify($current_pwd, $hash)) {
                    $password_errors[] = "Incorrect current password. Verification failed.";
                    audit_log('PASSWORD_CHANGE_FAILED', "User #{$user_id} supplied invalid current password", $user_id);
                } else {
                    // Hash new password
                    $new_hash = password_hash($new_pwd, PASSWORD_DEFAULT);
                    $up_stmt = $pdo->prepare("UPDATE users SET password = :pwd WHERE id = :id");
                    $up_stmt->execute([':pwd' => $new_hash, ':id' => $user_id]);

                    audit_log('PASSWORD_CHANGED', "User #{$user_id} updated their account password", $user_id);
                    set_flash('success', 'Password changed successfully! Your account is secured.');
                    header('Location: profile.php');
                    exit;
                }
            } catch (PDOException $e) {
                error_log("[Password Update Error] " . $e->getMessage());
                $password_errors[] = "Database error updating password.";
            }
        }
    }
}

$page_title = "Account Settings";
require_once __DIR__ . '/includes/header.php';
?>

<div style="max-width: 860px; margin: 0 auto;">
    <div style="margin-bottom: 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
        <div>
            <h1>Account &amp; Security Settings</h1>
            <p>Manage your personal profile, credentials, and security parameters.</p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
            <a href="export_tasks.php" class="btn btn-outline btn-sm">
                <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                Export My Tasks
            </a>
            <a href="dashboard.php" class="btn btn-teal btn-sm">&larr; Back to Dashboard</a>
        </div>
    </div>

    <!-- Account Overview Card -->
    <div class="card" style="margin-bottom: 2rem;">
        <div class="card-header">
            <h2 class="card-title">User Account Overview</h2>
            <span class="badge badge-completed"><?= e($db_user['status']); ?></span>
        </div>
        <div class="form-row">
            <div>
                <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">EMAIL ADDRESS</div>
                <div style="font-size: 1rem; font-weight: 700; color: var(--navy-900); margin-top: 0.25rem;">
                    <?= e($db_user['email']); ?>
                </div>
            </div>
            <div>
                <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">ROLE</div>
                <div style="margin-top: 0.25rem;">
                    <?php if (is_admin()): ?>
                        <span class="badge badge-high">Administrator</span>
                    <?php else: ?>
                        <span class="badge badge-low">Standard User</span>
                    <?php endif; ?>
                </div>
            </div>
            <div>
                <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">MEMBER SINCE</div>
                <div style="font-size: 1rem; font-weight: 600; color: var(--navy-800); margin-top: 0.25rem;">
                    <?= e(date('F d, Y', strtotime($db_user['created_at']))); ?>
                </div>
            </div>
            <div>
                <div style="font-size: 0.8rem; color: var(--slate-500); font-weight: 600;">TASK METRICS</div>
                <div style="font-size: 0.95rem; font-weight: 600; color: var(--teal-600); margin-top: 0.25rem;">
                    <?= (int)$task_stats['completed']; ?> / <?= (int)$task_stats['total']; ?> Completed
                </div>
            </div>
        </div>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem;">
        <!-- Edit Profile Name Card -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Update Profile Name</h3>
            </div>

            <?php if (!empty($profile_errors)): ?>
                <div class="alert alert-danger" role="alert">
                    <div class="alert-content">
                        <ul style="margin-left: 1rem;">
                            <?php foreach ($profile_errors as $err): ?>
                                <li><?= e($err); ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            <?php endif; ?>

            <form action="profile.php" method="POST">
                <?= csrf_field(); ?>
                <input type="hidden" name="action" value="update_profile">

                <div class="form-group">
                    <label for="name" class="form-label">Full Name <span class="required">*</span></label>
                    <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        class="form-control" 
                        value="<?= e($db_user['name']); ?>" 
                        required 
                        maxlength="100"
                    >
                </div>

                <button type="submit" class="btn btn-teal" style="width: 100%;">
                    Save Profile Changes
                </button>
            </form>
        </div>

        <!-- Change Password Card -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Change Password</h3>
            </div>

            <?php if (!empty($password_errors)): ?>
                <div class="alert alert-danger" role="alert">
                    <div class="alert-content">
                        <ul style="margin-left: 1rem;">
                            <?php foreach ($password_errors as $err): ?>
                                <li><?= e($err); ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            <?php endif; ?>

            <form action="profile.php" method="POST">
                <?= csrf_field(); ?>
                <input type="hidden" name="action" value="change_password">

                <div class="form-group">
                    <label for="current_password" class="form-label">Current Password <span class="required">*</span></label>
                    <input 
                        type="password" 
                        id="current_password" 
                        name="current_password" 
                        class="form-control" 
                        placeholder="Verify current password" 
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="new_password" class="form-label">New Password <span class="required">*</span></label>
                    <input 
                        type="password" 
                        id="new_password" 
                        name="new_password" 
                        class="form-control" 
                        placeholder="Min 8 chars (letters & numbers)" 
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="confirm_password" class="form-label">Confirm New Password <span class="required">*</span></label>
                    <input 
                        type="password" 
                        id="confirm_password" 
                        name="confirm_password" 
                        class="form-control" 
                        placeholder="Re-type new password" 
                        required
                    >
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%;">
                    Update Password
                </button>
            </form>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
