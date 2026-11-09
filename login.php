<?php
/**
 * ====================================================================
 * Secure Task Management System
 * User Authentication & Login Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Guest guard (redirects already logged-in users).
 * - CSRF token verification on POST.
 * - Input validation & sanitization.
 * - Prepared SQL queries preventing SQL injection.
 * - Timing attack / enumeration mitigation via unified error messages.
 * - Cryptographic password verification with password_verify().
 * - Session fixation immunity via session_regenerate_id(true).
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Redirect authenticated users directly to dashboard
require_guest();

$errors = [];
$email  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Validate CSRF Token
    validate_csrf();

    // 2. Sanitize Inputs
    $email    = sanitize_text($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // 3. Basic Validation
    if (empty($email) || empty($password)) {
        $errors[] = "Please provide both your email address and password.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please provide a valid email format.";
    }

    // 4. Authenticate User
    if (empty($errors)) {
        try {
            // SECURITY: Use prepared statement to retrieve candidate user
            $stmt = $pdo->prepare("SELECT id, name, email, password FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            // SECURITY: Verify password hash; use identical error for non-existent users
            // to prevent user enumeration attacks.
            if ($user && password_verify($password, $user['password'])) {
                // If password hash needs an upgrade to stronger settings, update it silently
                if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                    $new_hash = password_hash($password, PASSWORD_DEFAULT);
                    $update_stmt = $pdo->prepare("UPDATE users SET password = :pwd WHERE id = :id");
                    $update_stmt->execute([':pwd' => $new_hash, ':id' => $user['id']]);
                }

                // Initialize secure authenticated session with regenerated session ID
                login_user($user);

                set_flash('success', "Welcome back, " . htmlspecialchars($user['name']) . "!");
                header('Location: dashboard.php');
                exit;
            } else {
                // Generic error message prevents username/email enumeration
                $errors[] = "Invalid email address or password.";
            }
        } catch (PDOException $e) {
            error_log("[Login Error] " . $e->getMessage());
            $errors[] = "A system error occurred during login. Please try again.";
        }
    }
}

$page_title = "Login";
require_once __DIR__ . '/includes/header.php';
?>

<div class="auth-wrapper">
    <div class="auth-card">
        <div class="auth-header">
            <h1>Account Login</h1>
            <p>Access your secure tasks</p>
        </div>

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

        <form action="login.php" method="POST" novalidate>
            <?= csrf_field(); ?>

            <div class="form-group">
                <label for="email" class="form-label">Email Address <span class="required">*</span></label>
                <input 
                    type="email" 
                    id="email" 
                    name="email" 
                    class="form-control" 
                    placeholder="name@example.com" 
                    value="<?= e($email); ?>" 
                    required 
                    autocomplete="email"
                    autofocus
                >
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Password <span class="required">*</span></label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-control" 
                    placeholder="Enter your password" 
                    required 
                    autocomplete="current-password"
                >
            </div>

            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;">
                Sign In
            </button>
        </form>

        <div class="auth-footer">
            Don't have an account? <a href="register.php" style="font-weight: 600;">Create one now</a>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

