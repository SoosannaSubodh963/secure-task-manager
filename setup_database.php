<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Automatic Database Setup & Migration Script
 * 
 * Run via Browser: http://localhost/secure-task-manager/setup_database.php
 * Or via CLI:      php setup_database.php
 * ====================================================================
 */

$host = 'localhost';
$port = '3306';
$user = 'root';
$pass = '';

$is_cli = (php_sapi_name() === 'cli');

function output_msg($msg, $type = 'info') {
    global $is_cli;
    if ($is_cli) {
        echo "[" . strtoupper($type) . "] " . strip_tags($msg) . "\n";
    } else {
        $color = ($type === 'success') ? '#10b981' : (($type === 'error') ? '#ef4444' : '#0284c7');
        echo "<div style='font-family: sans-serif; padding: 10px 15px; margin: 8px 0; border-radius: 6px; background: " . (($type === 'error') ? '#fee2e2' : '#f0fdf4') . "; color: {$color}; border: 1px solid {$color};'><strong>" . htmlspecialchars($msg) . "</strong></div>";
    }
}

if (!$is_cli) {
    echo "<!DOCTYPE html><html><head><title>Database Setup</title><style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:20px;background:#0f172a;color:#f8fafc;}.card{background:#1e293b;padding:24px;border-radius:12px;border:1px solid #334155;}.btn{display:inline-block;background:#0d9488;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;margin-top:15px;}</style></head><body><div class='card'><h2>Database Auto-Setup</h2>";
}

try {
    // 1. Connect to MySQL server (without selecting database yet)
    $pdo = new PDO("mysql:host={$host};port={$port};charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    output_msg("Connected to MySQL server on {$host}:{$port} successfully.", "success");

    // 2. Read database.sql file
    $sql_file = __DIR__ . '/database/database.sql';
    if (!file_exists($sql_file)) {
        throw new Exception("File 'database/database.sql' was not found!");
    }

    $sql_content = file_get_contents($sql_file);

    // 3. Execute the full database.sql schema
    $pdo->exec($sql_content);
    output_msg("Database 'secure_task_manager' created successfully!", "success");
    output_msg("Tables 'users' and 'tasks' created successfully!", "success");
    output_msg("Demo data inserted successfully! (demo@securetask.local / Password123!)", "success");

    if (!$is_cli) {
        echo "<p style='color:#cbd5e1;margin-top:20px;'>Your database is completely setup and ready to use!</p>";
        echo "<a href='index.php' class='btn'>Go to Homepage &rarr;</a> ";
        echo "<a href='login.php' class='btn' style='background:#334155;margin-left:10px;'>Login Page</a>";
    }

} catch (PDOException $e) {
    output_msg("Database Setup Failed: " . $e->getMessage(), "error");
    if (!$is_cli) {
        echo "<p style='color:#cbd5e1;'>Please make sure MySQL is started in XAMPP Control Panel.</p>";
    }
} catch (Exception $e) {
    output_msg("Error: " . $e->getMessage(), "error");
}

if (!$is_cli) {
    echo "</div></body></html>";
}
