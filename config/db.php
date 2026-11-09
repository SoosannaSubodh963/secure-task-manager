<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Database Connection Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Uses PHP Data Objects (PDO) for secure, prepared SQL execution.
 * - Enforces PDO::ATTR_EMULATE_PREPARES => false to ensure real prepared
 *   statements are executed by the MySQL engine (SQLi immunity).
 * - Implements secure credential isolation (Environment variables or config.local.php).
 * - Automatic schema migration ensuring RBAC and audit logs are ready.
 * - Security event logging helper audit_log().
 * ====================================================================
 */

// Prevent direct script execution if accessed outside application scope
if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === 'db.php') {
    http_response_code(403);
    exit('Access Denied');
}

// 1. Default local XAMPP configuration
$db_host = 'localhost';
$db_port = '3306';
$db_name = 'secure_task_manager';
$db_user = 'root';
$db_pass = '';
$db_charset = 'utf8mb4';

// 2. Allow environment variables to override defaults (Ideal for CI/CD pipelines & Docker/Cloud)
if (getenv('DB_HOST'))    $db_host = getenv('DB_HOST');
if (getenv('DB_PORT'))    $db_port = getenv('DB_PORT');
if (getenv('DB_NAME'))    $db_name = getenv('DB_NAME');
if (getenv('DB_USER'))    $db_user = getenv('DB_USER');
if (getenv('DB_PASS') !== false) $db_pass = getenv('DB_PASS');

// 3. Optional local configuration file (ignored by Git for production secrets)
$local_config_file = __DIR__ . '/config.local.php';
if (file_exists($local_config_file)) {
    $local_cfg = include $local_config_file;
    if (is_array($local_cfg)) {
        $db_host = $local_cfg['host'] ?? $db_host;
        $db_port = $local_cfg['port'] ?? $db_port;
        $db_name = $local_cfg['name'] ?? $db_name;
        $db_user = $local_cfg['user'] ?? $db_user;
        $db_pass = $local_cfg['pass'] ?? $db_pass;
    }
}

// 4. Construct Data Source Name (DSN)
$dsn = "mysql:host={$db_host};port={$db_port};dbname={$db_name};charset={$db_charset}";

// 5. PDO Connection Options
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_PERSISTENT         => false,
];

try {
    $pdo = new PDO($dsn, $db_user, $db_pass, $options);
    auto_migrate_schema($pdo);
} catch (PDOException $e) {
    error_log("[Database Connection Error] " . $e->getMessage());

    http_response_code(500);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Database Error - Secure Task Manager</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 1rem; }
            .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; max-width: 550px; text-align: center; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
            h1 { color: #f87171; font-size: 1.5rem; margin-top: 0; }
            p { color: #cbd5e1; line-height: 1.6; font-size: 0.95rem; }
            .box { background: #0f172a; border-radius: 8px; padding: 1rem; text-align: left; font-family: monospace; font-size: 0.85rem; color: #38bdf8; margin: 1rem 0; overflow-x: auto; }
            .btn { display: inline-block; background: #0d9488; color: #fff; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 0.5rem; transition: background 0.2s; }
            .btn:hover { background: #0f766e; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Database Connection Notice</h1>
            <p>The application could not connect to MySQL. If you are running locally in XAMPP, please verify that:</p>
            <div class="box">
                1. The MySQL service is running in XAMPP Control Panel.<br>
                2. Run the one-click setup at <strong><a href="setup_database.php" style="color:#38bdf8;">setup_database.php</a></strong>.<br>
                3. Or import <strong>database/database.sql</strong> via phpMyAdmin.
            </div>
            <a href="index.php" class="btn">Retry Connection</a>
        </div>
    </body>
    </html>
    <?php
    exit;
}

/**
 * Automatically migrate database schema to include workflow approval and audit logging.
 * 
 * @param PDO $pdo
 * @return void
 */
function auto_migrate_schema(PDO $pdo): void {
    static $done = false;
    if ($done) return;

    try {
        // Ensure tasks table has approval_status and admin_notes
        $col_approval = $pdo->query("SHOW COLUMNS FROM tasks LIKE 'approval_status'");
        if (!$col_approval->fetch()) {
            $pdo->exec("ALTER TABLE tasks ADD COLUMN approval_status ENUM('Pending', 'Approved', 'Rejected') NOT NULL DEFAULT 'Approved'");
            $pdo->exec("ALTER TABLE tasks ADD COLUMN admin_notes VARCHAR(255) NULL");
            $pdo->exec("ALTER TABLE tasks ADD INDEX idx_tasks_approval_status (approval_status)");
        }

        // Ensure users table has status (Active / Suspended)
        $col_status = $pdo->query("SHOW COLUMNS FROM users LIKE 'status'");
        if (!$col_status->fetch()) {
            $pdo->exec("ALTER TABLE users ADD COLUMN status ENUM('Active', 'Suspended') NOT NULL DEFAULT 'Active'");
        }

        // Ensure audit_logs table exists
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                user_id INT UNSIGNED NULL,
                action VARCHAR(100) NOT NULL,
                details TEXT NULL,
                ip_address VARCHAR(45) NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY idx_audit_user_id (user_id),
                KEY idx_audit_action (action),
                KEY idx_audit_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ");

        $done = true;
    } catch (Throwable $e) {
        // Table might not exist yet if database.sql hasn't executed
    }
}

/**
 * Record a security or operational event to the DevSecOps audit log.
 * 
 * @param string $action Action identifier (e.g., 'LOGIN_SUCCESS', 'TASK_APPROVED')
 * @param string|null $details Descriptive details
 * @param int|null $user_id Acting user ID
 * @return void
 */
function audit_log(string $action, ?string $details = null, ?int $user_id = null): void {
    global $pdo;
    if (!$pdo) return;

    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        if ($user_id === null && function_exists('current_user_id')) {
            $user_id = current_user_id();
        }
        $stmt = $pdo->prepare("
            INSERT INTO audit_logs (user_id, action, details, ip_address)
            VALUES (:uid, :act, :det, :ip)
        ");
        $stmt->execute([
            ':uid' => $user_id,
            ':act' => $action,
            ':det' => $details,
            ':ip'  => $ip,
        ]);
    } catch (Throwable $e) {
        error_log("[Audit Log Write Error] " . $e->getMessage());
    }
}

/**
 * Helper function to retrieve database connection instance.
 * 
 * @return PDO
 */
function get_db(): PDO {
    global $pdo;
    return $pdo;
}
