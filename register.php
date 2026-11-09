<?php
/**
 * ====================================================================
 * Secure Task Management System
 * User Registration Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Guest guard (redirects already logged-in users).
 * - CSRF token verification on POST.
 * - Comprehensive input validation and sanitization.
 * - Prepared SQL statements preventing SQL injection.
 * - Password hashing using standard Bcrypt / Argon2 via password_hash().
 * ====================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/config/db.php';

// Redirect authenticated users away from registration
require_guest();

$errors = [];
$name   = '';
$email  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Validate CSRF Token
    validate_csrf();

    // 2. Sanitize & Retrieve Inputs
    $name             = sanitize_text($_POST['name'] ?? '');
    $email            = sanitize_text($_POST['email'] ?? '');
    $password         = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // 3. Validation Rules
    if (empty($name)) {
        $errors[] = "Full name is required.";
    } elseif (mb_strlen($name) < 2 || mb_strlen($name) > 100) {
        $errors[] = "Full name must be between 2 and 100 characters.";
    }

    if (empty($email)) {
        $errors[] = "Email address is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please provide a valid email address.";
    } elseif (mb_strlen($email) > 150) {
        $errors[] = "Email address cannot exceed 150 characters.";
    }

    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    } elseif (!preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must include both letters and numbers for adequate strength.";
    }

    if ($password !== $confirm_password) {
        $errors[] = "Password confirmation does not match.";
    }

    // 4. Duplicate Email Check (Prepared Statement)
    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            if ($stmt->fetch()) {
                $errors[] = "An account with that email address is already registered.";
            }
        } catch (PDOException $e) {
            error_log("[Registration Query Error] " . $e->getMessage());
            $errors[] = "An internal error occurred. Please try again later.";
        }
    }

    // 5. Account Creation
    if (empty($errors)) {
        try {
            // SECURITY: Hash password using strong algorithm (Bcrypt by default in PHP 8)
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            $insert_stmt = $pdo->prepare(
                "INSERT INTO users (name, email, password) VALUES (:name, :email, :password)"
            );
            $insert_stmt->execute([
                ':name'     => $name,
                ':email'    => $email,
                ':password' => $password_hash,
            ]);

            set_flash('success', 'Registration successful! You may now sign in with your credentials.');
            header('Location: login.php');
            exit;
        } catch (PDOException $e) {
            error_log("[Registration Insert Error] " . $e->getMessage());
            $errors[] = "Registration could not be completed. Please try again.";
        }
    }
}

$page_title = "Register";
require_once __DIR__ . '/includes/header.php';
?>

<div class="auth-wrapper">
    <div class="auth-card">
        <div class="auth-header">
            <h1>Create Account</h1>
            <p>Join the Secure Task Management System</p>
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

        <form action="register.php" method="POST" id="registerForm" novalidate>
            <?= csrf_field(); ?>

            <div class="form-group">
                <label for="name" class="form-label">Full Name <span class="required">*</span></label>
                <input 
                    type="text" 
                    id="name" 
                    name="name" 
                    class="form-control" 
                    placeholder="e.g. Jane Doe" 
                    value="<?= e($name); ?>" 
                    required 
                    autocomplete="name"
                >
            </div>

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
                >
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Password <span class="required">*</span></label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-control" 
                    placeholder="Minimum 8 characters (letters & numbers)" 
                    required 
                    autocomplete="new-password"
                >
                <small class="form-text">Must be at least 8 characters and include letters & numbers.</small>
            </div>

            <div class="form-group">
                <label for="confirm_password" class="form-label">Confirm Password <span class="required">*</span></label>
                <input 
                    type="password" 
                    id="confirm_password" 
                    name="confirm_password" 
                    class="form-control" 
                    placeholder="Re-enter your password" 
                    required 
                    autocomplete="new-password"
                >
                <small id="passwordMatchError" class="form-text" style="color: var(--danger); display: none;">
                    Passwords do not match.
                </small>
            </div>

            <button type="submit" class="btn btn-teal" style="width: 100%; margin-top: 0.5rem;">
                Create My Account
            </button>
        </form>

        <div class="auth-footer">
            Already have an account? <a href="login.php" style="font-weight: 600;">Sign in here</a>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
