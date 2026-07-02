-- =============================================================================
-- SAN Blog System – MySQL Schema
-- Execute this on your MySQL server to create the blog database
-- =============================================================================

CREATE DATABASE IF NOT EXISTS san_blog
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE san_blog;

-- ---------------------------------------------------------------------------
-- Categories
-- ---------------------------------------------------------------------------
CREATE TABLE categories (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100)  NOT NULL UNIQUE,
    slug        VARCHAR(120)  NOT NULL UNIQUE,
    description TEXT          NULL,
    created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Tags
-- ---------------------------------------------------------------------------
CREATE TABLE tags (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(80)   NOT NULL UNIQUE,
    slug        VARCHAR(100)  NOT NULL UNIQUE,
    created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Posts
-- ---------------------------------------------------------------------------
CREATE TABLE posts (
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
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Post ↔ Categories (many-to-many)
-- ---------------------------------------------------------------------------
CREATE TABLE post_categories (
    post_id     INT UNSIGNED NOT NULL,
    category_id INT UNSIGNED NOT NULL,

    PRIMARY KEY (post_id, category_id),
    FOREIGN KEY (post_id)     REFERENCES posts(id)      ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Post ↔ Tags (many-to-many)
-- ---------------------------------------------------------------------------
CREATE TABLE post_tags (
    post_id INT UNSIGNED NOT NULL,
    tag_id  INT UNSIGNED NOT NULL,

    PRIMARY KEY (post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id)  REFERENCES tags(id)  ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Comments
-- ---------------------------------------------------------------------------
CREATE TABLE comments (
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
) ENGINE=InnoDB;
