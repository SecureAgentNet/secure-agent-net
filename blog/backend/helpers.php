<?php
// =============================================================================
// SAN Blog – Helper Functions
// =============================================================================

require_once __DIR__ . '/database.php';

/**
 * Send a JSON response and exit.
 */
function jsonResponse(mixed $data, int $statusCode = 200): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Read JSON request body.
 */
function jsonInput(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

/**
 * Validate required fields exist in an array.
 */
function requireFields(array $data, array $fields): void
{
    $missing = [];
    foreach ($fields as $field) {
        if (!isset($data[$field]) || $data[$field] === '') {
            $missing[] = $field;
        }
    }
    if (!empty($missing)) {
        jsonResponse([
            'error'   => 'Missing required fields',
            'missing' => $missing,
        ], 400);
    }
}

/**
 * Generate a URL-safe slug from a string.
 */
function slugify(string $text): string
{
    $text = strtolower(trim($text));
    $text = preg_replace('/[^a-z0-9\s-]/', '', $text);
    $text = preg_replace('/[\s]+/', '-', $text);
    $text = preg_replace('/-+/', '-', $text);
    return trim($text, '-');
}

/**
 * Fetch tags for a given post ID.
 */
function getPostTags(PDO $db, int $postId): array
{
    $stmt = $db->prepare('
        SELECT t.id, t.name, t.slug
        FROM tags t
        INNER JOIN post_tags pt ON t.id = pt.tag_id
        WHERE pt.post_id = :pid
    ');
    $stmt->execute(['pid' => $postId]);
    return $stmt->fetchAll();
}

/**
 * Fetch categories for a given post ID.
 */
function getPostCategories(PDO $db, int $postId): array
{
    $stmt = $db->prepare('
        SELECT c.id, c.name, c.slug
        FROM categories c
        INNER JOIN post_categories pc ON c.id = pc.category_id
        WHERE pc.post_id = :pid
    ');
    $stmt->execute(['pid' => $postId]);
    return $stmt->fetchAll();
}

/**
 * Sync many-to-many tags for a post.
 */
function syncPostTags(PDO $db, int $postId, array $tagNames): void
{
    $db->prepare('DELETE FROM post_tags WHERE post_id = :pid')->execute(['pid' => $postId]);

    foreach ($tagNames as $name) {
        $name = trim($name);
        if ($name === '') continue;

        $slug = slugify($name);

        $stmt = $db->prepare('SELECT id FROM tags WHERE slug = :slug');
        $stmt->execute(['slug' => $slug]);
        $tag = $stmt->fetch();

        if (!$tag) {
            $db->prepare('INSERT INTO tags (name, slug) VALUES (:name, :slug)')
               ->execute(['name' => $name, 'slug' => $slug]);
            $tagId = (int) $db->lastInsertId();
        } else {
            $tagId = (int) $tag['id'];
        }

        $db->prepare('INSERT INTO post_tags (post_id, tag_id) VALUES (:pid, :tid)')
           ->execute(['pid' => $postId, 'tid' => $tagId]);
    }
}

/**
 * Sync many-to-many categories for a post.
 */
function syncPostCategories(PDO $db, int $postId, array $categoryNames): void
{
    $db->prepare('DELETE FROM post_categories WHERE post_id = :pid')->execute(['pid' => $postId]);

    foreach ($categoryNames as $name) {
        $name = trim($name);
        if ($name === '') continue;

        $slug = slugify($name);

        $stmt = $db->prepare('SELECT id FROM categories WHERE slug = :slug');
        $stmt->execute(['slug' => $slug]);
        $cat = $stmt->fetch();

        if (!$cat) {
            $db->prepare('INSERT INTO categories (name, slug) VALUES (:name, :slug)')
               ->execute(['name' => $name, 'slug' => $slug]);
            $catId = (int) $db->lastInsertId();
        } else {
            $catId = (int) $cat['id'];
        }

        $db->prepare('INSERT INTO post_categories (post_id, category_id) VALUES (:pid, :cid)')
           ->execute(['pid' => $postId, 'cid' => $catId]);
    }
}

/**
 * Handle CORS preflight OPTIONS request.
 */
function handleCors(): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization');
        http_response_code(204);
        exit;
    }
}
