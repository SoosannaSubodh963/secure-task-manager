<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Global Header Template
 * ====================================================================
 */

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/csrf.php';

$current_page = basename($_SERVER['PHP_SELF'] ?? '');
$is_auth = is_logged_in();
$user = $is_auth ? current_user() : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isset($page_title) ? e($page_title) . ' | SecureTask' : 'Secure Task Management System'; ?></title>
    <!-- Stylesheet -->
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

    <!-- Global Navigation Bar -->
    <header class="navbar">
        <div class="container nav-container">
            <a href="<?= $is_auth ? 'dashboard.php' : 'index.php'; ?>" class="brand-logo" aria-label="SecureTask Home">
                <div class="brand-icon">
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                </div>
                <span>SecureTask</span>
            </a>

            <nav>
                <ul class="nav-links">
                    <?php if ($is_auth): ?>
                        <li>
                            <a href="dashboard.php" class="nav-link <?= ($current_page === 'dashboard.php') ? 'active' : ''; ?>">
                                Dashboard
                            </a>
                        </li>
                        <?php if (is_admin()): ?>
                            <li>
                                <a href="admin.php" class="nav-link <?= ($current_page === 'admin.php') ? 'active' : ''; ?>" style="color: var(--danger); font-weight: 700;">
                                    Admin Panel
                                </a>
                            </li>
                        <?php endif; ?>
                        <li>
                            <a href="add_task.php" class="btn btn-teal btn-sm">
                                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"></path></svg>
                                New Task
                            </a>
                        </li>
                        <li>
                            <div class="nav-user">
                                <span class="nav-user-dot"></span>
                                <span><?= e($user['name'] ?? 'User'); ?></span>
                            </div>
                        </li>
                        <li>
                            <form action="logout.php" method="POST" style="display:inline;">
                                <?= csrf_field(); ?>
                                <button type="submit" class="btn btn-outline btn-sm" title="Log out safely">
                                    Logout
                                </button>
                            </form>
                        </li>
                    <?php else: ?>
                        <li>
                            <a href="index.php" class="nav-link <?= ($current_page === 'index.php') ? 'active' : ''; ?>">Home</a>
                        </li>
                        <li>
                            <a href="login.php" class="nav-link <?= ($current_page === 'login.php') ? 'active' : ''; ?>">Login</a>
                        </li>
                        <li>
                            <a href="register.php" class="btn btn-primary btn-sm">Get Started</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </nav>
        </div>
    </header>

    <!-- Main Content Wrapper -->
    <main class="main-content">
        <div class="container">
            <!-- Flash Message Alerts -->
            <?php $flashes = get_flashes(); ?>
            <?php if (!empty($flashes)): ?>
                <div class="alerts-container">
                    <?php foreach ($flashes as $flash): ?>
                        <div class="alert alert-<?= e($flash['type']); ?>" role="alert">
                            <div class="alert-content">
                                <?php if ($flash['type'] === 'success'): ?>
                                    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
                                <?php elseif ($flash['type'] === 'danger'): ?>
                                    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
                                <?php else: ?>
                                    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>
                                <?php endif; ?>
                                <span><?= e($flash['message']); ?></span>
                            </div>
                            <button type="button" class="alert-close" aria-label="Close alert">&times;</button>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

