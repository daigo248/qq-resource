DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS codes;
CREATE TABLE codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    requires_login BOOLEAN DEFAULT 1,
    view_limit INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS views;
CREATE TABLE views (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, resource_id)
);

DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT DEFAULT 'text', -- 新增：'text' 或 'image'
    requires_login BOOLEAN DEFAULT 1,
    view_limit INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- 其他表保持不变，为了方便你可以保留之前的 users, codes, views 表定义
-- 注意：在 Cloudflare D1 Console 里如果你已经有很多数据，只需要运行 ALTER TABLE resources ADD COLUMN type TEXT DEFAULT 'text';
-- 如果是新项目，直接用全量 SQL 覆盖即可。
