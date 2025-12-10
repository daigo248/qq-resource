import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono().basePath('/api');

// 辅助函数
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

// 1. 发送验证码 (普通用户)
app.post('/auth/send-code', async (c) => {
  const { email } = await c.req.json();
  if (!/^[1-9][0-9]{4,}@qq\.com$/.test(email)) return c.json({ error: '必须使用有效的QQ邮箱' }, 400);
  
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  
  await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, expires_at) VALUES (?, ?, ?)').bind(email, code, expiresAt).run();
  
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${c.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'onboarding@resend.dev', to: email, subject: '登录验证码', html: `<p>验证码: <strong>${code}</strong></p>` })
  });
  if (!res.ok) return c.json({ error: '邮件发送失败' }, 500);
  return c.json({ message: '验证码已发送' });
});

// 2. 登录 (区分管理员和普通用户)
app.post('/auth/login', async (c) => {
  const { email, code, isAdmin } = await c.req.json();

  // 管理员登录逻辑
  if (isAdmin) {
    if (email === c.env.ADMIN_USER && code === c.env.ADMIN_PASSWD) {
      const token = await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET);
      return c.json({ token, role: 'admin' });
    }
    return c.json({ error: '管理员账号或密码错误' }, 400);
  }

  // 普通用户逻辑
  const record = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ?').bind(email).first();
  if (!record || record.code !== code || Date.now() > record.expires_at) return c.json({ error: '验证码错误' }, 400);

  let user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) user = await c.env.DB.prepare('INSERT INTO users (email) VALUES (?) RETURNING *').bind(email).first();

  const token = await signToken({ id: user.id, role: 'user', email: user.email }, c.env.JWT_SECRET);
  return c.json({ token, role: 'user', email: user.email });
});

// 3. 获取资源 (含权限)
app.get('/resources', async (c) => {
  const list = await c.env.DB.prepare('SELECT id, title, requires_login, view_limit, type, created_at FROM resources ORDER BY id DESC').all();
  return c.json(list.results);
});

app.get('/resource/:id', async (c) => {
  const id = c.req.param('id');
  const token = c.req.header('Authorization')?.split(' ')[1];
  let user = null;
  if (token) user = await verifyToken(token, c.env.JWT_SECRET);

  const resource = await c.env.DB.prepare('SELECT * FROM resources WHERE id = ?').bind(id).first();
  if (!resource) return c.json({ error: '资源不存在' }, 404);

  // 权限检查
  if (resource.requires_login === 1 && !user) return c.json({ error: '请先登录' }, 401);
  
  if (resource.view_limit > 0 && (!user || user.role !== 'admin')) {
    const view = await c.env.DB.prepare('SELECT count FROM views WHERE user_id = ? AND resource_id = ?').bind(user.id, id).first();
    if (view && view.count >= resource.view_limit) return c.json({ error: `次数已用尽` }, 403);
    
    // 计数
    if (!view) await c.env.DB.prepare('INSERT INTO views (user_id, resource_id, count) VALUES (?, ?, 1)').bind(user.id, id).run();
    else await c.env.DB.prepare('UPDATE views SET count = count + 1 WHERE user_id = ? AND resource_id = ?').bind(user.id, id).run();
  }

  return c.json({ content: resource.content, type: resource.type });
});

// 4. 发布资源 (支持图片上传)
app.post('/admin/create', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

  const body = await c.req.parseBody();
  const title = body['title'];
  const requires_login = body['requires_login'] === 'true' ? 1 : 0;
  const view_limit = parseInt(body['view_limit'] || 0);
  const file = body['file']; // 图片文件
  const textContent = body['content']; // 文字内容

  let finalContent = textContent;
  let type = 'text';

  // 如果上传了文件
  if (file && file instanceof File) {
    const fileName = `${Date.now()}-${file.name}`;
    // 上传到 R2
    await c.env.BUCKET.put(fileName, file.stream(), {
      httpMetadata: { contentType: file.type }
    });
    // 拼接成图片地址
    finalContent = `${c.env.R2_DOMAIN}/${fileName}`;
    type = 'image';
  }

  await c.env.DB.prepare(
    'INSERT INTO resources (title, content, requires_login, view_limit, type) VALUES (?, ?, ?, ?, ?)'
  ).bind(title, finalContent, requires_login, view_limit, type).run();

  return c.json({ success: true });
});

export const onRequest = handle(app);
