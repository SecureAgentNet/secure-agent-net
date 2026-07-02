<?php
/**
 * SAN Blog – One-Click Deployment Script
 * ========================================
 * Upload this file to: blog/backend/deploy.php
 * Then open it in your browser: https://secureagentnet.com/blog/backend/deploy.php
 * Delete this file after successful deployment.
 */

// --- Config (double-check these match config.php) ---
define('DB_HOST',    'localhost');
define('DB_USER',    'bdgkwy_0');
define('DB_PASS',    'd2}F=(1*#oEY');
define('DB_NAME',    'san_blog');
define('DB_CHARSET', 'utf8mb4');

set_time_limit(60);
error_reporting(E_ALL);
ini_set('display_errors', '1');

$messages = [];

function log_msg(string $msg, string $type = 'info'): void {
    global $messages;
    $messages[] = ['text' => $msg, 'type' => $type];
}

try {
    // Step 1: Connect without database
    $dsnNoDb = sprintf('mysql:host=%s;charset=%s', DB_HOST, DB_CHARSET);
    $pdo = new PDO($dsnNoDb, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    log_msg('MySQL connection established.', 'success');

    // Step 2: Create database if not exists
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    log_msg("Database '" . DB_NAME . "' ready.", 'success');

    // Step 3: Select database
    $pdo->exec("USE `" . DB_NAME . "`");
    log_msg("Using database '" . DB_NAME . "'.", 'success');

    // Step 4: Create tables
    $tables = [];

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS categories (
            id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(100)  NOT NULL UNIQUE,
            slug        VARCHAR(120)  NOT NULL UNIQUE,
            description TEXT          NULL,
            created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB
    ");
    $tables[] = 'categories';

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS tags (
            id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(80)   NOT NULL UNIQUE,
            slug        VARCHAR(100)  NOT NULL UNIQUE,
            created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB
    ");
    $tables[] = 'tags';

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS posts (
            id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            title          VARCHAR(255)  NOT NULL,
            slug           VARCHAR(255)  NOT NULL UNIQUE,
            summary        TEXT          NULL,
            body           LONGTEXT      NOT NULL,
            cover_image    VARCHAR(512)  NULL,
            status         ENUM('draft','published') NOT NULL DEFAULT 'draft',
            author         VARCHAR(120)  NOT NULL DEFAULT 'SAN Operator',
            read_time      VARCHAR(20)   NOT NULL DEFAULT '5 MIN',
            published_at   TIMESTAMP     NULL DEFAULT NULL,
            created_at     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_status   (status),
            INDEX idx_published (published_at),
            INDEX idx_author   (author)
        ) ENGINE=InnoDB
    ");
    $tables[] = 'posts';

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS post_categories (
            post_id     INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (post_id, category_id),
            FOREIGN KEY (post_id)     REFERENCES posts(id)      ON DELETE CASCADE,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB
    ");
    $tables[] = 'post_categories';

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS post_tags (
            post_id INT UNSIGNED NOT NULL,
            tag_id  INT UNSIGNED NOT NULL,
            PRIMARY KEY (post_id, tag_id),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id)  REFERENCES tags(id)  ON DELETE CASCADE
        ) ENGINE=InnoDB
    ");
    $tables[] = 'post_tags';

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS comments (
            id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            post_id      INT UNSIGNED  NOT NULL,
            parent_id    INT UNSIGNED  NULL DEFAULT NULL,
            author_name  VARCHAR(100)  NOT NULL,
            author_email VARCHAR(255)  NOT NULL,
            body         TEXT          NOT NULL,
            is_approved  TINYINT(1)    NOT NULL DEFAULT 0,
            created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_post     (post_id),
            INDEX idx_approved (is_approved),
            FOREIGN KEY (post_id)   REFERENCES posts(id)    ON DELETE CASCADE,
            FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE SET NULL
        ) ENGINE=InnoDB
    ");
    $tables[] = 'comments';

    log_msg('Tables created: ' . implode(', ', $tables), 'success');

    // Step 5: Verify tables
    $existing = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
    log_msg('Existing tables: ' . implode(', ', $existing), 'success');

    // Step 6: Insert sample categories & tags
    $pdo->exec("INSERT IGNORE INTO categories (name, slug) VALUES
        ('ITCD Research', 'itcd-research'),
        ('Threat Intelligence', 'threat-intelligence'),
        ('Engineering', 'engineering'),
        ('Compliance', 'compliance')
    ");
    $pdo->exec("INSERT IGNORE INTO tags (name, slug) VALUES
        ('ZeroTrust', 'zerotrust'),
        ('LLM Audit', 'llm-audit'),
        ('K8s', 'k8s'),
        ('CloudSec', 'cloudsec'),
        ('Prompt Injection', 'prompt-injection'),
        ('Swarm Security', 'swarm-security')
    ");

    // Step 7: Insert a sample post
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM posts');
    $stmt->execute();
    $postCount = (int) $stmt->fetchColumn();

    if ($postCount === 0) {
        $pdo->exec("INSERT INTO posts (title, slug, summary, body, status, author, read_time, published_at) VALUES (
            'Welcome to the SAN Intelligence Mesh',
            'welcome-san-intelligence-mesh',
            'Your blog system is fully deployed and operational. This is a sample post to verify everything works.',
            '# Welcome to the SAN Blog\n\nThis post confirms your blog system is fully deployed on your Hetzner Managed Server.\n\n## What is working\n\n- **MySQL Database** — All 6 tables created successfully\n- **PHP REST API** — Endpoints serving JSON responses\n- **Astro.js Frontend** — Static site fetching posts dynamically\n- **Admin Panel** — Password-protected editor at `/blog/backend/admin/`\n\n## Next Steps\n\n1. Log into the admin panel and change your password\n2. Create your first real post\n3. Customize the frontend styling\n\n---\n\n*Published via SAN Blog Deployment Script*',
            'published',
            'SAN Operator',
            '3 MIN',
            NOW()
        )");
        log_msg('Sample post created.', 'success');
    } else {
        log_msg("Already $postCount post(s) in database. Skipping sample.", 'info');
    }

    log_msg('DEPLOYMENT COMPLETE!', 'success');

} catch (PDOException $e) {
    log_msg('Database error: ' . $e->getMessage(), 'error');
} catch (Exception $e) {
    log_msg('Error: ' . $e->getMessage(), 'error');
}

// --- Render output ---
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SAN Blog – Deployment</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'JetBrains Mono', monospace; background: #0f131d; color: #dfe2f1; min-height: 100vh; padding: 2rem; }
        h1 { color: #4cd7f6; font-size: 1.5rem; margin-bottom: 1.5rem; }
        .log { background: rgba(28,31,42,0.6); border: 1px solid rgba(255,255,255,0.05); border-radius: 0.75rem; padding: 1.5rem; max-width: 700px; margin: 0 auto; }
        .entry { padding: 0.5rem 0.75rem; margin-bottom: 0.25rem; border-radius: 0.375rem; font-size: 0.85rem; }
        .entry.success { color: #4edea3; background: rgba(78,222,163,0.1); border-left: 3px solid #4edea3; }
        .entry.error   { color: #ffb4ab; background: rgba(255,180,171,0.1); border-left: 3px solid #ffb4ab; }
        .entry.info    { color: #bcc9cd; background: rgba(255,255,255,0.03); border-left: 3px solid #4cd7f6; }
        .footer { margin-top: 2rem; color: #869397; font-size: 0.75rem; text-align: center; }
        .footer a { color: #4cd7f6; }
    </style>
</head>
<body>
    <h1>SAN Blog :: Deployment</h1>
    <div class="log">
        <?php foreach ($messages as $m): ?>
            <div class="entry <?= $m['type'] ?>"><?= htmlspecialchars($m['text']) ?></div>
        <?php endforeach; ?>
    </div>
    <div class="footer">
        <p>Delete this file (<code>deploy.php</code>) after verifying everything works.</p>
        <p><a href="https://secureagentnet.com/blog/backend/admin/">Go to Admin Panel</a> | <a href="https://secureagentnet.com/blog">View Blog</a></p>
    </div>
</body>
</html>
