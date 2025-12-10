import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono().basePath('/api');

// === 工具函数 ===
async function signToken(payload, secret) {
  const secretKey = new TextEncoder().encode(secret);
  return await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setExpirationTime('7d').sign(secretKey);
}
async function verifyToken(token, secret) {
  try {
    const secretKey = new TextEncoder().encode(secret);
    return (await jwtVerify(token, secretKey)).payload;
  } catch (e) { return null; }
}
// 简单的 SHA-256 哈希
async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// === Brevo API 发信 ===
async function sendEmail(env, to, subject, html) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({
      sender: { email: env.SENDER_EMAIL, name: "蓝鲸小站" },
      to: [{ email: to }], subject, htmlContent: html
    })
  });
  if (!res.ok) throw new Error(await res.text());
}

// === 1. 发送验证码 (注册/重置) ===
app.post('/auth/send-code', async (c) => {
  const { email, type } = await c.req.json(); // type: 'register' or 'reset'
  if (!/^[1-9][0-9]{4,}@qq\.com$/.test(email)) return c.json({ error: '仅支持QQ邮箱' }, 400);

  // 检查是否已注册
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (type === 'register' && user) return c.json({ error: '该邮箱已注册，请直接登录' }, 400);
  if (type === 'reset' && !user) return c.json({ error: '该邮箱未注册' }, 400);
  
  // 3天限制检查
  if (type === 'reset' && user && user.last_reset_at) {
    const daysSinceReset = (Date.now() - user.last_reset_at) / (1000 * 60 * 60 * 24);
    if (daysSinceReset < 3) return c.json({ error: '密码重置太频繁，请3天后再试' }, 400);
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)').bind(email, code, type, Date.now() + 300000).run();
  
  await sendEmail(c.env, email, `【蓝鲸小站】${type==='register'?'注册':'重置密码'}验证码`, `<p>验证码: <b>${code}</b></p>`);
  return c.json({ success: true });
});

// === 2. 注册 (设置用户名密码) ===
app.post('/auth/register', async (c) => {
  const { email, code, username, password } = await c.req.json();
  const record = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "register"').bind(email).first();
  if (!record || record.code !== code || Date.now() > record.expires_at) return c.json({ error: '验证码无效' }, 400);

  // 检查用户名唯一
  const exist = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (exist) return c.json({ error: '用户名已被占用' }, 400);

  const pwdHash = await hashPassword(password);
  const res = await c.env.DB.prepare('INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?) RETURNING *').bind(email, username, pwdHash).first();
  
  // 注册成功自动登录
  const token = await signToken({ id: res.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user: { username: res.username, email: res.email, role: 'user' } });
});

// === 3. 登录 (邮箱或用户名 + 密码) ===
app.post('/auth/login', async (c) => {
  const { loginId, password, isAdmin } = await c.req.json();

  // 管理员特例
  if (isAdmin) {
    if (loginId === c.env.ADMIN_USER && password === c.env.ADMIN_PASSWD) {
      const token = await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET);
      return c.json({ token, user: { username: 'Admin', role: 'admin' } });
    }
    return c.json({ error: '管理员认证失败' }, 400);
  }

  const pwdHash = await hashPassword(password);
  // 支持 邮箱 或 用户名 登录
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE (email = ? OR username = ?) AND password_hash = ?')
    .bind(loginId, loginId, pwdHash).first();

  if (!user) return c.json({ error: '账号或密码错误' }, 400);

  const token = await signToken({ id: user.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user: { username: user.username, email: user.email, role: user.role } });
});

// === 4. 重置密码 ===
app.post('/auth/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json();
  const record = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "reset"').bind(email).first();
  if (!record || record.code !== code || Date.now() > record.expires_at) return c.json({ error: '验证码无效' }, 400);

  const pwdHash = await hashPassword(newPassword);
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, last_reset_at = ? WHERE email = ?')
    .bind(pwdHash, Date.now(), email).run();
  
  return c.json({ success: true });
});

// === 5. 获取公共数据 (分类 + 文章列表) ===
app.get('/public/home', async (c) => {
  const categories = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all();
  // 获取文章列表，但要把 content_json 里的敏感信息隐藏
  const resources = await c.env.DB.prepare(`
    SELECT r.id, r.title, r.category_id, r.content_json, r.created_at, c.name as category_name 
    FROM resources r LEFT JOIN categories c ON r.category_id = c.id 
    ORDER BY r.id DESC
  `).all();

  const safeResources = resources.results.map(r => {
    let content = [];
    try { content = JSON.parse(r.content_json); } catch(e){}
    // 数据脱敏：如果是 locked 的块，把 value 替换掉
    const safeContent = content.map(block => {
      if (block.locked) return { ...block, value: '*** 内容受限，点击解锁 ***', isLockedMask: true };
      return block;
    });
    return { ...r, content: safeContent };
  });

  return c.json({ categories: categories.results, resources: safeResources });
});

// === 6. 解锁内容 (核心扣费逻辑) ===
app.post('/resource/unlock', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const userPayload = await verifyToken(token, c.env.JWT_SECRET);
  if (!userPayload) return c.json({ error: '请先登录' }, 401);
  if (userPayload.role === 'admin') return c.json({ error: '管理员无需解锁' }); // 管理员直接看原版

  const { resourceId, blockIndex } = await c.req.json();
  const userId = userPayload.id;
  const today = new Date().toISOString().split('T')[0]; // "2025-12-10"

  // 1. 获取用户信息和配额
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  
  // 计算今日限额
  let dailyLimit = user.default_quota || 5;
  if (user.temp_quota_config) {
    try {
      const conf = JSON.parse(user.temp_quota_config); // {start, end, limit}
      if (today >= conf.start && today <= conf.end) dailyLimit = conf.limit;
    } catch(e) {}
  }

  // 2. 获取今日已用次数
  const usageRecord = await c.env.DB.prepare('SELECT view_count FROM daily_usage WHERE user_id = ? AND date_str = ?').bind(userId, today).first();
  const used = usageRecord ? usageRecord.view_count : 0;

  if (used >= dailyLimit) return c.json({ error: `今日配额已用完 (${used}/${dailyLimit})` }, 403);

  // 3. 扣费 (增加使用次数)
  await c.env.DB.prepare(`
    INSERT INTO daily_usage (user_id, date_str, view_count) VALUES (?, ?, 1)
    ON CONFLICT(user_id, date_str) DO UPDATE SET view_count = view_count + 1
  `).bind(userId, today).run();

  // 4. 返回那个块的真实内容
  const resource = await c.env.DB.prepare('SELECT content_json FROM resources WHERE id = ?').bind(resourceId).first();
  const content = JSON.parse(resource.content_json);
  const targetBlock = content[blockIndex];

  return c.json({ 
    realValue: targetBlock.value, 
    remaining: dailyLimit - used - 1 
  });
});

// === 7. 管理员 API ===
// 发布资源
app.post('/admin/resource', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

  const { title, category_id, blocks } = await c.req.json();
  // blocks 结构: [{type: 'text', value: 'xx'}, {type: 'link', value: 'http', locked: true}]
  await c.env.DB.prepare('INSERT INTO resources (title, category_id, content_json) VALUES (?, ?, ?)').bind(title, category_id, JSON.stringify(blocks)).run();
  return c.json({ success: true });
});

// 删除资源
app.post('/admin/resource/delete', async (c) => {
    const token = c.req.header('Authorization')?.split(' ')[1];
    const user = await verifyToken(token, c.env.JWT_SECRET);
    if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);
    const { id } = await c.req.json();
    await c.env.DB.prepare('DELETE FROM resources WHERE id = ?').bind(id).run();
    return c.json({ success: true });
});

// 管理分类
app.post('/admin/category', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  
  const { action, name, id } = await c.req.json();
  if(action === 'add') await c.env.DB.prepare('INSERT INTO categories (name) VALUES (?)').bind(name).run();
  if(action === 'del') await c.env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
  return c.json({ success: true });
});

// 用户管理 (列表 & 修改配额)
app.get('/admin/users', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  
  const users = await c.env.DB.prepare('SELECT id, username, email, default_quota, temp_quota_config, created_at FROM users WHERE role != "admin" ORDER BY id DESC').all();
  return c.json(users.results);
});

app.post('/admin/user/quota', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

  const { userId, config } = await c.req.json(); // config = {start, end, limit} 或 null
  await c.env.DB.prepare('UPDATE users SET temp_quota_config = ? WHERE id = ?').bind(config ? JSON.stringify(config) : null, userId).run();
  return c.json({ success: true });
});

// 图片上传 (R2)
app.post('/admin/upload', async (c) => {
    const token = c.req.header('Authorization')?.split(' ')[1];
    const user = await verifyToken(token, c.env.JWT_SECRET);
    if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

    const body = await c.req.parseBody();
    const file = body['file'];
    if(file && file.name) {
        const fileName = `${Date.now()}-${file.name}`;
        await c.env.BUCKET.put(fileName, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
        return c.json({ url: `${c.env.R2_DOMAIN}/${fileName}` });
    }
    return c.json({ error: '文件无效' }, 400);
});

export const onRequest = handle(app);
