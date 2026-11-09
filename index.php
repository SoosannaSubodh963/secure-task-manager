<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Landing Page
 * 
 * Features:
 * - Professional presentation for academic startup demonstration.
 * - Architecture highlights: Cloud Computing, DevOps, and Cybersecurity.
 * - Call-to-action buttons for registration, login, and dashboard access.
 * ====================================================================
 */

$page_title = "Modern & Secure Task Management";
require_once __DIR__ . '/includes/header.php';
?>

<!-- Hero Section -->
<section class="hero-section">
    <div class="hero-pill">
        <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
        Cloud Computing &bull; DevOps &bull; Cybersecurity
    </div>

    <h1 class="hero-title">
        Manage Tasks With Confidence &bull; Built For <span class="text-gradient">Ironclad Security</span>
    </h1>

    <p class="hero-subtitle">
        A lightweight, high-performance task management application developed with Core PHP and MySQL.
        Engineered from the ground up to prevent OWASP Top 10 vulnerabilities while streamlining everyday workflows.
    </p>

    <div class="hero-cta">
        <?php if ($is_auth): ?>
            <a href="dashboard.php" class="btn btn-teal btn-lg">Go To Dashboard &rarr;</a>
        <?php else: ?>
            <a href="register.php" class="btn btn-teal btn-lg">Create Free Account</a>
            <a href="login.php" class="btn btn-outline btn-lg">Account Login</a>
        <?php endif; ?>
    </div>
</section>

<!-- Feature Highlights -->
<section class="features-section">
    <div class="section-header">
        <h2>Engineered for Productivity & Defense</h2>
        <p>Combining modern user experience with enterprise-grade security primitives.</p>
    </div>

    <div class="features-grid">
        <div class="feature-card">
            <div class="feature-icon-wrapper">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path></svg>
            </div>
            <h3>Full Task CRUD Lifecycle</h3>
            <p>Create, inspect, modify, and delete tasks effortlessly. Filter dynamically by pending, completed, or priority status.</p>
        </div>

        <div class="feature-card">
            <div class="feature-icon-wrapper">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            </div>
            <h3>OWASP Defense-in-Depth</h3>
            <p>Prepared SQL queries, strict session isolation, CSRF tokens on all mutations, Bcrypt hashing, and automated XSS escaping.</p>
        </div>

        <div class="feature-card">
            <div class="feature-icon-wrapper">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
            </div>
            <h3>DevOps & CI/CD Ready</h3>
            <p>Includes a GitHub Actions continuous integration pipeline enforcing PHP syntax checks, automated testing, and security audits.</p>
        </div>

        <div class="feature-card">
            <div class="feature-icon-wrapper">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
            </div>
            <h3>Cloud-Scalable Design</h3>
            <p>Environment-driven configuration enables effortless transition from local XAMPP to Docker containers and cloud providers.</p>
        </div>
    </div>
</section>

<!-- Academic Pillar Showcase -->
<section class="academic-banner">
    <div>
        <h3>Academic Startup Architecture</h3>
        <h2>The Triad of Modern Software Engineering</h2>
        <p>
            This system bridges foundational web development with industry DevSecOps standards,
            demonstrating how security and automated quality checks are integrated directly into the development lifecycle.
        </p>
        <div style="display: flex; gap: 0.75rem;">
            <a href="register.php" class="btn btn-teal">Start Managing Tasks</a>
            <a href="login.php" class="btn btn-outline" style="border-color: rgba(255,255,255,0.2); color:#fff;">Sign In</a>
        </div>
    </div>
    <div>
        <ul class="pillars-list">
            <li class="pillar-item">
                <span class="pillar-badge">Cloud</span>
                <span>Container-compatible decoupled architecture ready for AWS RDS & EC2</span>
            </li>
            <li class="pillar-item">
                <span class="pillar-badge">DevOps</span>
                <span>GitHub Actions CI automation for syntax validation and regression tests</span>
            </li>
            <li class="pillar-item">
                <span class="pillar-badge">Security</span>
                <span>Strict multi-tenant authorization preventing IDOR and data leakage</span>
            </li>
        </ul>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

