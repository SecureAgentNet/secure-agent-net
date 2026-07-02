<?php
// =============================================================================
// SAN Blog – Admin Post Editor (Create & Edit)
// =============================================================================

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/../helpers.php';

requireLogin();

$db    = getDB();
$post  = null;
$editMode = false;

// Load existing post for editing
$editId = $_GET['id'] ?? null;
if ($editId) {
    $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id');
    $stmt->execute(['id' => (int) $editId]);
    $post = $stmt->fetch();
    if ($post) {
        $editMode = true;
        $post['tags']       = getPostTags($db, (int) $post['id']);
        $post['categories'] = getPostCategories($db, (int) $post['id']);
        $tagNames = array_map(fn($t) => $t['name'], $post['tags']);
        $catNames = array_map(fn($c) => $c['name'], $post['categories']);
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title      = trim($_POST['title'] ?? '');
    $slug       = trim($_POST['slug'] ?? '') ?: slugify($title);
    $body       = $_POST['body'] ?? '';
    $summary    = trim($_POST['summary'] ?? '');
    $author     = trim($_POST['author'] ?? '');
    $readTime   = trim($_POST['read_time'] ?? '5 MIN');
    $coverImage = trim($_POST['cover_image'] ?? '');
    $status     = ($_POST['status'] ?? 'draft') === 'published' ? 'published' : 'draft';
    $tags       = array_filter(array_map('trim', explode(',', $_POST['tags'] ?? '')));
    $categories = array_filter(array_map('trim', explode(',', $_POST['categories'] ?? '')));

    if (empty($title) || empty($body)) {
        $msg = 'Title and body are required.';
        $msgType = 'error';
    } else {
        $publishedAt = ($status === 'published') ? date('Y-m-d H:i:s') : null;

        if ($editMode) {
            $updateStmt = $db->prepare('
                UPDATE posts SET title=:title, slug=:slug, summary=:summary, body=:body,
                cover_image=:cover, status=:status, author=:author, read_time=:read_time,
                published_at=:published_at
                WHERE id=:id
            ');
            $updateStmt->execute([
                'title'        => $title,
                'slug'         => $slug,
                'summary'      => $summary,
                'body'         => $body,
                'cover'        => $coverImage,
                'status'       => $status,
                'author'       => $author,
                'read_time'    => $readTime,
                'published_at' => $publishedAt,
                'id'           => (int) $editId,
            ]);
            $postId = (int) $editId;
        } else {
            $insertStmt = $db->prepare('
                INSERT INTO posts (title, slug, summary, body, cover_image, status, author, read_time, published_at)
                VALUES (:title, :slug, :summary, :body, :cover, :status, :author, :read_time, :published_at)
            ');
            $insertStmt->execute([
                'title'        => $title,
                'slug'         => $slug,
                'summary'      => $summary,
                'body'         => $body,
                'cover'        => $coverImage,
                'status'       => $status,
                'author'       => $author,
                'read_time'    => $readTime,
                'published_at' => $publishedAt,
            ]);
            $postId = (int) $db->lastInsertId();
        }

        syncPostTags($db, $postId, $tags);
        syncPostCategories($db, $postId, $categories);

        header('Location: dashboard.php?msg=' . ($editMode ? 'updated' : 'created'));
        exit;
    }
}

$msg     = $msg ?? '';
$msgType = $msgType ?? '';
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SAN Blog Admin – <?= $editMode ? 'Edit' : 'New' ?> Post</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" rel="stylesheet" />
    <script>
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        background: "#0f131d",
                        surface: "#1c1f2a",
                        primary: "#4cd7f6",
                        secondary: "#4edea3",
                        "on-background": "#dfe2f1",
                        "on-surface-variant": "#bcc9cd",
                        outline: "#869397",
                        "outline-variant": "#3d494c",
                        error: "#ffb4ab",
                    }
                }
            }
        }
    </script>
    <style>
        .markdown-preview { min-height: 200px; }
        .markdown-preview h1 { font-size: 2rem; font-weight: 600; margin: 1.5rem 0 0.75rem; border-left: 4px solid #4cd7f6; padding-left: 0.75rem; color: #dfe2f1; }
        .markdown-preview h2 { font-size: 1.5rem; font-weight: 600; margin: 1.25rem 0 0.5rem; color: #dfe2f1; }
        .markdown-preview p { margin-bottom: 1rem; color: #bcc9cd; line-height: 1.7; }
        .markdown-preview a { color: #4cd7f6; text-decoration: underline; }
        .markdown-preview code { font-family: monospace; background: rgba(255,255,255,0.05); padding: 0.2rem 0.4rem; border-radius: 0.25rem; color: #4cd7f6; }
        .markdown-preview pre { background: #0b0f19; border: 1px solid rgba(255,255,255,0.08); border-radius: 0.5rem; padding: 1rem; overflow-x: auto; }
        .markdown-preview pre code { background: transparent; padding: 0; color: #dfe2f1; }
        .markdown-preview ul { list-style: disc; padding-left: 1.5rem; margin-bottom: 1rem; color: #bcc9cd; }
        .markdown-preview ol { list-style: decimal; padding-left: 1.5rem; margin-bottom: 1rem; color: #bcc9cd; }
        .markdown-preview img { max-width: 100%; border-radius: 0.5rem; margin: 1rem 0; }
        .markdown-preview blockquote { border-left: 4px solid #4cd7f6; padding-left: 1rem; font-style: italic; color: #4cd7f6; margin: 1rem 0; background: rgba(76,215,246,0.05); padding: 0.5rem 1rem; }
    </style>
</head>
<body class="bg-background text-on-background min-h-screen"
      style="background-image: radial-gradient(circle at 2px 2px, rgba(6,182,212,0.03) 1px, transparent 0); background-size: 32px 32px;">

    <!-- Header -->
    <header class="border-b border-white/5 bg-surface/70 backdrop-blur-xl sticky top-0 z-50">
        <div class="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
            <div class="flex items-center gap-6">
                <a href="dashboard.php" class="text-on-surface-variant hover:text-primary transition-colors">
                    <span class="material-symbols-outlined">arrow_back</span>
                </a>
                <h1 class="text-primary font-bold text-lg"><?= $editMode ? 'Edit Post' : 'New Post' ?></h1>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-6 py-8">
        <?php if ($msg): ?>
            <div class="mb-6 p-3 rounded-lg text-sm <?= $msgType === 'error' ? 'bg-red-900/20 border border-red-500/30 text-error' : 'bg-green-900/20 border border-green-500/30 text-secondary' ?>">
                <?= htmlspecialchars($msg) ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="space-y-6">
            <!-- Meta fields -->
            <div class="bg-surface/50 border border-white/5 rounded-xl p-6 grid grid-cols-1 md:grid-cols-2 gap-5">
                <div class="md:col-span-2">
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Title *</label>
                    <input type="text" name="title" required
                           value="<?= htmlspecialchars($post['title'] ?? '') ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none text-lg font-semibold" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Slug</label>
                    <input type="text" name="slug"
                           value="<?= htmlspecialchars($post['slug'] ?? '') ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none font-mono text-sm" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Author</label>
                    <input type="text" name="author"
                           value="<?= htmlspecialchars($post['author'] ?? 'SAN Operator') ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Read Time</label>
                    <input type="text" name="read_time"
                           value="<?= htmlspecialchars($post['read_time'] ?? '5 MIN') ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none font-mono" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Cover Image URL</label>
                    <input type="text" name="cover_image"
                           value="<?= htmlspecialchars($post['cover_image'] ?? '') ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none font-mono text-sm" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Status</label>
                    <select name="status" class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none">
                        <option value="draft" <?= (($post['status'] ?? '') === 'draft') ? 'selected' : '' ?>>Draft</option>
                        <option value="published" <?= (($post['status'] ?? '') === 'published') ? 'selected' : '' ?>>Published</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Tags (comma separated)</label>
                    <input type="text" name="tags"
                           value="<?= htmlspecialchars(implode(', ', $tagNames ?? [])) ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none font-mono text-sm" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Categories (comma separated)</label>
                    <input type="text" name="categories"
                           value="<?= htmlspecialchars(implode(', ', $catNames ?? [])) ?>"
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none font-mono text-sm" />
                </div>
                <div class="md:col-span-2">
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase">Summary</label>
                    <textarea name="summary" rows="2"
                              class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none resize-y"><?= htmlspecialchars($post['summary'] ?? '') ?></textarea>
                </div>
            </div>

            <!-- Editor tabs -->
            <div class="bg-surface/50 border border-white/5 rounded-xl overflow-hidden">
                <div class="flex border-b border-white/5">
                    <button type="button" id="tabWrite" class="px-5 py-2.5 text-sm font-mono text-primary border-b-2 border-primary bg-primary/5 transition-colors">Write (Markdown)</button>
                    <button type="button" id="tabPreview" class="px-5 py-2.5 text-sm font-mono text-outline-variant hover:text-primary transition-colors">Preview</button>
                </div>

                <div id="writePane" class="p-4">
                    <textarea name="body" id="bodyEditor" rows="20"
                              class="w-full bg-black/30 border-0 p-4 text-on-background font-mono text-sm outline-none resize-y min-h-[400px]"
                              placeholder="# Start writing in Markdown..."><?= htmlspecialchars($post['body'] ?? '') ?></textarea>
                </div>

                <div id="previewPane" class="p-6 hidden markdown-preview">
                    <div id="previewContent" class="prose-invert max-w-none"></div>
                </div>
            </div>

            <div class="flex gap-4 justify-end">
                <a href="dashboard.php" class="border border-outline-variant text-on-surface-variant px-6 py-3 rounded-lg hover:border-primary hover:text-primary transition-all text-sm font-semibold">Cancel</a>
                <button type="submit" class="bg-primary text-black font-bold px-8 py-3 rounded-lg hover:shadow-[0_0_15px_rgba(76,215,246,0.3)] transition-all">
                    <?= $editMode ? 'Update Post' : 'Publish Post' ?>
                </button>
            </div>
        </form>
    </main>

    <!-- Markdown.js for preview -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script>
        const tabWrite = document.getElementById('tabWrite');
        const tabPreview = document.getElementById('tabPreview');
        const writePane = document.getElementById('writePane');
        const previewPane = document.getElementById('previewPane');
        const bodyEditor = document.getElementById('bodyEditor');
        const previewContent = document.getElementById('previewContent');

        tabWrite.addEventListener('click', () => {
            tabWrite.className = 'px-5 py-2.5 text-sm font-mono text-primary border-b-2 border-primary bg-primary/5 transition-colors';
            tabPreview.className = 'px-5 py-2.5 text-sm font-mono text-outline-variant hover:text-primary transition-colors';
            writePane.classList.remove('hidden');
            previewPane.classList.add('hidden');
        });

        tabPreview.addEventListener('click', () => {
            tabPreview.className = 'px-5 py-2.5 text-sm font-mono text-primary border-b-2 border-primary bg-primary/5 transition-colors';
            tabWrite.className = 'px-5 py-2.5 text-sm font-mono text-outline-variant hover:text-primary transition-colors';
            writePane.classList.add('hidden');
            previewPane.classList.remove('hidden');
            previewContent.innerHTML = marked.parse(bodyEditor.value);
        });

        // Auto-slug from title
        document.querySelector('[name="title"]').addEventListener('input', function() {
            const slugInput = document.querySelector('[name="slug"]');
            if (slugInput && !slugInput.dataset.manual) {
                slugInput.value = this.value.toLowerCase()
                    .replace(/[^a-z0-9\s-]/g, '')
                    .replace(/\s+/g, '-')
                    .replace(/-+/g, '-');
            }
        });
        document.querySelector('[name="slug"]').addEventListener('input', function() {
            this.dataset.manual = '1';
        });
    </script>
</body>
</html>
