-- 1. 用户表 (大幅升级)
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,       -- 用户名
    password_hash TEXT,         -- 密码哈希
    role TEXT DEFAULT 'user',
    default_quota INTEGER DEFAULT 5, -- 默认每天5次
    temp_quota_config TEXT,     -- JSON字段: {"start":"2025-12-11","end":"2025-12-13","limit":20}
    last_reset_at INTEGER DEFAULT 0, -- 上次重置密码时间
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 验证码表
DROP TABLE IF EXISTS codes;
CREATE TABLE codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    type TEXT DEFAULT 'login', -- 'register' 或 'reset'
    expires_at INTEGER NOT NULL
);

-- 3. 版块/分类表 (新增)
DROP TABLE IF EXISTS categories;
CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sort_order INTEGER DEFAULT 0
);
-- 初始化默认分类
INSERT INTO categories (name) VALUES ('综合'), ('电视剧'), ('综艺'), ('动漫');

-- 4. 资源表 (结构变更)
DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category_id INTEGER,
    -- content 将存储 JSON 数组，例如:
    -- [{"type":"text","val":"..."}, {"type":"link","val":"http..","locked":true}]
    content_json TEXT NOT NULL, 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. 用户每日使用记录表 (用于限制每天次数)
DROP TABLE IF EXISTS daily_usage;
CREATE TABLE daily_usage (
    user_id INTEGER NOT NULL,
    date_str TEXT NOT NULL, -- 格式 "YYYY-MM-DD"
    view_count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, date_str)
);
