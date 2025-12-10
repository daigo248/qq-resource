-- 1. 用户表 (新增配额计算字段)
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    -- 配额相关
    daily_limit INTEGER DEFAULT 1,   -- 当前每日额度 (根据规则动态变动 1-3)
    last_calc_date TEXT,             -- 上次计算额度的日期 (YYYY-MM-DD)
    last_unlock_date TEXT,           -- 上次实际解锁的日期 (YYYY-MM-DD)
    
    temp_quota_config TEXT,          -- 管理员强制指定的临时规则
    last_reset_at INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 验证码表
DROP TABLE IF EXISTS codes;
CREATE TABLE codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    type TEXT DEFAULT 'login',
    expires_at INTEGER NOT NULL
);

-- 3. 分类表
DROP TABLE IF EXISTS categories;
CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sort_order INTEGER DEFAULT 0
);
INSERT INTO categories (name) VALUES ('综合'), ('电视剧'), ('综艺'), ('动漫');

-- 4. 资源表 (新增 custom_date 字段)
DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category_id INTEGER,
    content_json TEXT NOT NULL, 
    custom_date TEXT, -- 自动识别或手填的日期 (例如 "2025年12月8日")
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. 每日使用计数表 (仅用于计数，逻辑已变，但保留用于统计)
DROP TABLE IF EXISTS daily_usage;
CREATE TABLE daily_usage (
    user_id INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    view_count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, date_str)
);

-- 6. 解锁记录表 (新: 记录具体解锁了哪个帖子，当天重复看不用扣次)
DROP TABLE IF EXISTS unlocked_items;
CREATE TABLE unlocked_items (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    date_str TEXT NOT NULL, -- YYYY-MM-DD
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, resource_id, date_str)
);

-- 7. 评论表 (新)
DROP TABLE IF EXISTS comments;
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. 点赞表 (新)
DROP TABLE IF EXISTS likes;
CREATE TABLE likes (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, resource_id)
);
