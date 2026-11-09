<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Automated Test Runner (CI/CD & Local Verification)
 * 
 * Verifies core security primitives and application logic without
 * requiring an active database server in CI runners.
 * ====================================================================
 */

// Load Application Includes before sending any output to allow session initialization
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';

// Define test counters
$tests_run = 0;
$tests_passed = 0;
$tests_failed = 0;

function run_test(string $name, callable $test_fn) {
    global $tests_run, $tests_passed, $tests_failed;
    $tests_run++;
    echo "[TEST {$tests_run}] {$name}... ";
    try {
        $result = $test_fn();
        if ($result === true) {
            $tests_passed++;
            echo "PASSED\n";
        } else {
            $tests_failed++;
            echo "FAILED (Returned false or non-true)\n";
        }
    } catch (Throwable $e) {
        $tests_failed++;
        echo "FAILED: " . $e->getMessage() . "\n";
    }
}

echo "========================================================\n";
echo " SECURE TASK MANAGEMENT SYSTEM - AUTOMATED TEST SUITE   \n";
echo "========================================================\n\n";

// Test 1: XSS Output Escaping
run_test("Output Escaping (XSS Prevention)", function() {
    $malicious = '<script>alert("XSS")</script>&"\'';
    $escaped = e($malicious);
    
    // Must escape dangerous HTML entities
    if (strpos($escaped, '<script>') !== false) return false;
    if (strpos($escaped, '&lt;script&gt;') === false) return false;
    if (strpos($escaped, '&quot;') === false) return false;
    if (strpos($escaped, '&#039;') === false && strpos($escaped, '&apos;') === false) return false;
    return true;
});

// Test 2: Input Sanitization
run_test("Input Sanitization (Null Byte and Trim Filtering)", function() {
    $dirty = "   Clean Title \0 With Null Byte   ";
    $cleaned = sanitize_text($dirty);
    return ($cleaned === "Clean Title  With Null Byte");
});

// Test 3: Password Cryptographic Hashing & Verification
run_test("Password Cryptographic Hashing (Bcrypt)", function() {
    $password = "Secur3P@ssw0rd!2026";
    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    // Verify valid verification
    if (!password_verify($password, $hash)) return false;
    // Verify incorrect password rejected
    if (password_verify("WrongPassword", $hash)) return false;
    // Verify password is not stored plaintext
    if ($hash === $password) return false;
    return true;
});

// Test 4: CSRF Token Generation & Verification
run_test("CSRF Token Synchronizer Generation & Verification", function() {
    $token = generate_csrf_token();
    if (strlen($token) !== 64) return false; // 32 bytes hex = 64 chars
    
    // Valid token check
    if (!verify_csrf_token($token)) return false;
    // Tampered token check
    if (verify_csrf_token($token . 'invalid')) return false;
    // Empty token check
    if (verify_csrf_token('')) return false;
    if (verify_csrf_token(null)) return false;
    return true;
});

// Test 5: Session Cookie Security Settings Check
run_test("Session Cookie Security Parameter Configuration", function() {
    $params = session_get_cookie_params();
    if ($params['httponly'] !== true) return false;
    if (strcasecmp($params['samesite'] ?? '', 'Lax') !== 0) return false;
    return true;
});

// Test 6: Database SQL Schema Verification
run_test("Database Schema Script Integrity", function() {
    $sql_path = __DIR__ . '/../database/database.sql';
    if (!file_exists($sql_path)) return false;
    $sql = file_get_contents($sql_path);
    
    // Check key table and constraint definitions
    if (strpos($sql, 'CREATE TABLE IF NOT EXISTS `users`') === false) return false;
    if (strpos($sql, 'CREATE TABLE IF NOT EXISTS `tasks`') === false) return false;
    if (!preg_match('/FOREIGN\s+KEY\s*\(`user_id`\)\s*REFERENCES\s*`users`\s*\(`id`\)/i', $sql)) return false;
    return true;
});

// Test 7: Static Security Audit: Ensure No Raw Unescaped SQL Concatenation
run_test("Static Code Security Audit (No Raw SQL Concatenation)", function() {
    $files = glob(__DIR__ . '/../*.php');
    foreach ($files as $file) {
        $content = file_get_contents($file);
        // Look for dangerous patterns like "WHERE user_id = " . $user_id
        if (preg_match('/(SELECT|UPDATE|DELETE|INSERT)[^;]+WHERE[^;]+\$[a-zA-Z_]/i', $content, $matches)) {
            echo "\nPotential unparameterized query in " . basename($file) . ": " . $matches[0] . "\n";
            return false;
        }
    }
    return true;
});

// Summary Report
echo "\n========================================================\n";
echo " TEST EXECUTION SUMMARY\n";
echo " Total Tests:  {$tests_run}\n";
echo " Passed:       {$tests_passed}\n";
echo " Failed:       {$tests_failed}\n";
echo "========================================================\n";

if ($tests_failed > 0) {
    exit(1);
} else {
    echo " ALL TESTS COMPLETED SUCCESSFULLY! \n\n";
    exit(0);
}
