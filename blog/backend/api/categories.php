<?php
// =============================================================================
// SAN Blog – API: Categories
// Endpoints:
//   GET  /api/categories       – list all categories
//   GET  /api/categories/{slug} – posts by category
// =============================================================================

require_once __DIR__ . '/../helpers.php';

handleCors();

$method  = $_SERVER['REQUEST_METHOD'];
$db      = getDB();
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$identifier = null;
if (preg_match('#/api/categories(?:/([^/]+))?#', $requestUri, $m)) {
    $identifier = $m[1] ?? null;
}

// --- GET /api/categories ---
if ($method === 'GET' && !$identifier) {
    $stmt = $db->query('
        SELECT c.*, COUNT(pc.post_id) AS post_count
        FROM categories c
        LEFT JOIN post_categories pc ON c.id = pc.category_id
        GROUP BY c.id
        ORDER BY c.name ASC
    ');
    jsonResponse($stmt->fetchAll());
}

// --- GET /api/categories/{slug} (posts by category) ---
if ($method === 'GET' && $identifier) {
    $stmt = $db->prepare('SELECT id, name, slug FROM categories WHERE slug = :slug');
    $stmt->execute(['slug' => $identifier]);
    $category = $stmt->fetch();

    if (!$category) {
        jsonResponse(['error' => 'Category not found'], 404);
    }

    $page   = max(1, (int) ($_GET['page'] ?? 1));
    $limit  = min(50, max(1, (int) ($_GET['limit'] ?? 12)));
    $offset = ($page - 1) * $limit;

    $countStmt = $db->prepare('
        SELECT COUNT(*)
        FROM posts p
        INNER JOIN post_categories pc ON p.id = pc.post_id
        WHERE pc.category_id = :cid AND p.status = \'published\'
    ');
    $countStmt->execute(['cid' => $category['id']]);
    $total = (int) $countStmt->fetchColumn();

    $postStmt = $db->prepare('
        SELECT p.id, p.title, p.slug, p.summary, p.cover_image, p.author, p.read_time, p.published_at, p.created_at
        FROM posts p
        INNER JOIN post_categories pc ON p.id = pc.post_id
        WHERE pc.category_id = :cid AND p.status = \'published\'
        ORDER BY p.published_at DESC
        LIMIT :limit OFFSET :offset
    ');

    // Bind limit/offset as integers
    $postStmt->bindValue('cid', $category['id'], PDO::PARAM_INT);
    $postStmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $postStmt->bindValue('offset', $offset, PDO::PARAM_INT);
    $postStmt->execute();
    $posts = $postStmt->fetchAll();

    foreach ($posts as &$post) {
        $post['tags'] = getPostTags($db, (int) $post['id']);
    }

    jsonResponse([
        'category'   => $category,
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
