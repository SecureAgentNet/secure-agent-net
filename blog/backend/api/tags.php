<?php
// =============================================================================
// SAN Blog – API: Tags
// Endpoints:
//   GET  /api/tags       – list all tags
//   GET  /api/tags/{slug} – posts by tag
// =============================================================================

require_once __DIR__ . '/../helpers.php';

handleCors();

$method  = $_SERVER['REQUEST_METHOD'];
$db      = getDB();
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$identifier = null;
if (preg_match('#/api/tags(?:/([^/]+))?#', $requestUri, $m)) {
    $identifier = $m[1] ?? null;
}

// --- GET /api/tags ---
if ($method === 'GET' && !$identifier) {
    $stmt = $db->query('
        SELECT t.*, COUNT(pt.post_id) AS post_count
        FROM tags t
        LEFT JOIN post_tags pt ON t.id = pt.tag_id
        GROUP BY t.id
        ORDER BY post_count DESC, t.name ASC
    ');
    jsonResponse($stmt->fetchAll());
}

// --- GET /api/tags/{slug} (posts by tag) ---
if ($method === 'GET' && $identifier) {
    $stmt = $db->prepare('SELECT id, name, slug FROM tags WHERE slug = :slug');
    $stmt->execute(['slug' => $identifier]);
    $tag = $stmt->fetch();

    if (!$tag) {
        jsonResponse(['error' => 'Tag not found'], 404);
    }

    $page   = max(1, (int) ($_GET['page'] ?? 1));
    $limit  = min(50, max(1, (int) ($_GET['limit'] ?? 12)));
    $offset = ($page - 1) * $limit;

    $countStmt = $db->prepare('
        SELECT COUNT(*)
        FROM posts p
        INNER JOIN post_tags pt ON p.id = pt.post_id
        WHERE pt.tag_id = :tid AND p.status = \'published\'
    ');
    $countStmt->execute(['tid' => $tag['id']]);
    $total = (int) $countStmt->fetchColumn();

    $postStmt = $db->prepare('
        SELECT p.id, p.title, p.slug, p.summary, p.cover_image, p.author, p.read_time, p.published_at, p.created_at
        FROM posts p
        INNER JOIN post_tags pt ON p.id = pt.post_id
        WHERE pt.tag_id = :tid AND p.status = \'published\'
        ORDER BY p.published_at DESC
        LIMIT :limit OFFSET :offset
    ');

    $postStmt->bindValue('tid', $tag['id'], PDO::PARAM_INT);
    $postStmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $postStmt->bindValue('offset', $offset, PDO::PARAM_INT);
    $postStmt->execute();
    $posts = $postStmt->fetchAll();

    foreach ($posts as &$post) {
        $post['categories'] = getPostCategories($db, (int) $post['id']);
    }

    jsonResponse([
        'tag'        => $tag,
        'data'       => $posts,
        'pagination' => [
            'page'  => $page,
            'limit' => $limit,
            'total' => $total,
            'totalPages' => (int) ceil($total / $limit),
        ],
    ]);
}

jsonResponse(['error' => 'Method not allowed'], 405);
