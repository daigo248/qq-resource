-- 1-13. 原有表结构保持不变 (users, blacklist, codes, categories, resources, tags, resource_tags, daily_usage, unlocked_items, comments, likes, messages)
-- 请保留之前的 SQL，直接替换最后一张表 tag_keywords：

DROP TABLE IF EXISTS users;
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', daily_limit INTEGER DEFAULT 3, is_muted BOOLEAN DEFAULT 0, last_calc_date TEXT, last_unlock_date TEXT, temp_quota_config TEXT, last_reset_at INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
DROP TABLE IF EXISTS blacklist;
CREATE TABLE blacklist (email TEXT PRIMARY KEY, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
DROP TABLE IF EXISTS codes;
CREATE TABLE codes (email TEXT PRIMARY KEY, code TEXT NOT NULL, type TEXT DEFAULT 'login', expires_at INTEGER NOT NULL);
DROP TABLE IF EXISTS categories;
CREATE TABLE categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, sort_order INTEGER DEFAULT 0);
INSERT INTO categories (name) VALUES ('综合'), ('电视剧'), ('综艺'), ('动漫');
DROP TABLE IF EXISTS resources;
CREATE TABLE resources (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category_id INTEGER, content_json TEXT NOT NULL, custom_date TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
DROP TABLE IF EXISTS tags;
CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, image_url TEXT, UNIQUE(name, type));
DROP TABLE IF EXISTS resource_tags;
CREATE TABLE resource_tags (resource_id INTEGER NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (resource_id, tag_id));
DROP TABLE IF EXISTS daily_usage;
CREATE TABLE daily_usage (user_id INTEGER NOT NULL, date_str TEXT NOT NULL, view_count INTEGER DEFAULT 0, PRIMARY KEY (user_id, date_str));
DROP TABLE IF EXISTS unlocked_items;
CREATE TABLE unlocked_items (user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL, date_str TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (user_id, resource_id, date_str));
DROP TABLE IF EXISTS comments;
CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
DROP TABLE IF EXISTS likes;
CREATE TABLE likes (user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL, PRIMARY KEY (user_id, resource_id));
DROP TABLE IF EXISTS messages;
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, sender TEXT DEFAULT 'user', content TEXT NOT NULL, is_read BOOLEAN DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

-- 14. 标签自动关联规则表 (结构变更)
DROP TABLE IF EXISTS tag_keywords;
CREATE TABLE tag_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL,        -- 关键词 (不再唯一)
    tag_name TEXT NOT NULL,       -- 关联的标签名
    tag_type TEXT NOT NULL,       -- 关联的标签类型
    UNIQUE(keyword, tag_name, tag_type) -- 联合唯一：允许同个关键词关联不同标签
);
-- 原有表结构保持不变...
-- 为了方便，请直接在文件末尾添加或替换以下内容：

-- 1-14 表结构保持不变...
-- (users, blacklist, codes, categories, resources, tags, resource_tags, daily_usage, unlocked_items, comments, likes, messages, tag_keywords)

-- ... (保留上面所有的 CREATE TABLE 语句) ...

-- 15. 【新】API 速率限制表 (用于防刷)
DROP TABLE IF EXISTS rate_limits;
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL, -- 邮箱或IP
    endpoint TEXT NOT NULL,   -- 接口名 (如 send-code)
    created_at INTEGER NOT NULL
);

-- 16. 【新】搜索性能优化索引 (不存数据，只加速查询)
-- 给标题、日期、标签名加索引，加速 LIKE 查询和 JOIN
CREATE INDEX IF NOT EXISTS idx_resources_title ON resources(title);
CREATE INDEX IF NOT EXISTS idx_resources_date ON resources(custom_date);
CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id, is_read);
