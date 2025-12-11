-- 1. 用户表
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    daily_limit INTEGER DEFAULT 3,
    is_muted BOOLEAN DEFAULT 0,
    last_calc_date TEXT,
    last_unlock_date TEXT,
    temp_quota_config TEXT,
    last_reset_at INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 黑名单表
DROP TABLE IF EXISTS blacklist;
CREATE TABLE blacklist (
    email TEXT PRIMARY KEY,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. 验证码表
DROP TABLE IF EXISTS codes;
CREATE TABLE codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    type TEXT DEFAULT 'login',
    expires_at INTEGER NOT NULL
);

-- 4. 分类表 (原有)
DROP TABLE IF EXISTS categories;
CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sort_order INTEGER DEFAULT 0
);
INSERT INTO categories (name) VALUES ('综合'), ('电视剧'), ('综艺'), ('动漫');

-- 5. 资源表
DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category_id INTEGER,
    content_json TEXT NOT NULL, 
    custom_date TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. 标签表 (新)
-- type: '番组' 或 '艺人'
DROP TABLE IF EXISTS tags;
CREATE TABLE tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, -- 标签值
    type TEXT NOT NULL, -- 标签种类
    image_url TEXT,     -- 标签图片
    UNIQUE(name, type)
);

-- 7. 资源-标签关联表 (新)
DROP TABLE IF EXISTS resource_tags;
CREATE TABLE resource_tags (
    resource_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (resource_id, tag_id)
);

-- 8. 每日计数表
DROP TABLE IF EXISTS daily_usage;
CREATE TABLE daily_usage (
    user_id INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    view_count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, date_str)
);

-- 9. 解锁记录表
DROP TABLE IF EXISTS unlocked_items;
CREATE TABLE unlocked_items (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, resource_id, date_str)
);

-- 10. 评论表
DROP TABLE IF EXISTS comments;
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 11. 点赞表
DROP TABLE IF EXISTS likes;
CREATE TABLE likes (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, resource_id)
);

-- 12. 私信表
DROP TABLE IF EXISTS messages;
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sender TEXT DEFAULT 'user',
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
