import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono().basePath('/api');

// 辅助：生成 JWT
async function signToken(payload, secret) {
  const secretKey = new TextEncoder().encode(secret);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('7d')
    .sign(secretKey);
}

// 辅助：验证 JWT
async function verifyToken(token, secret) {
  try {
    const secretKey = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, secretKey);
    return payload;
  } catch (e) {
    return null;
  }
}

// 1. 发送验证码 (仅限普通 QQ 用户)
app.post('/auth/send-code', async (c) => {
  const { email } = await c.req.json();
  
  // 如果输入的是管理员账号，直接返回成功（实际不发邮件，为了前端流程通畅）
  if (email === c.env.ADMIN_USER) {
    return c.json({ message: '请输入管理员密码' });
  }

  // 校验 QQ 邮箱
  if (!/^[1-9][0-9]{4,}@qq\.com$/.test(email)) {
    return c.json({ error: '必须使用有效的QQ邮箱' }, 400);
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, expires_at) VALUES (?, ?, ?)')
    .bind(email, code, expiresAt).run();

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${c.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'onboarding@resend.dev',
      to: email,
      subject: '登录验证码',
      html: `<p>验证码: <strong>${code}</strong></p>`
    })
  });

  if (!res.ok) return c.json({ error: '邮件发送失败' }, 500);
  return c.json({ message: '验证码已发送' });
});

// 2. 登录 (双逻辑：管理员密码验证 OR 普通用户验证码)
app.post('/auth/login', async (c) => {
  const { email, code } = await c.req.json();

  // === 逻辑 A: 管理员登录 ===
  // 检查是否匹配环境变量中的 ADMIN_USER 和 ADMIN_PASSWD
  if (email === c.env.ADMIN_USER) {
    if (code === c.env.ADMIN_PASSWD) {
      // 这里的 code 字段此时被当作密码使用
      const token = await signToken({ id: 0, role: 'admin', email: 'Admin' }, c.env.JWT_SECRET);
      return c.json({ token, role: 'admin', email: 'Admin' });
    } else {
      return c.json({ error: '管理员密码错误' }, 400);
    }
  }

  // === 逻辑 B: 普通用户登录 ===
  const record = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ?').bind(email).first();
  if (!record || record.code !== code || Date.now() > record.expires_at) {
    return c.json({ error: '验证码错误或已过期' }, 400);
  }

  let user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) {
    const res = await c.env.DB.prepare('INSERT INTO users (email) VALUES (?) RETURNING *').bind(email).first();
    user = res;
  }

  const token = await signToken({ id: user.id, role: 'user', email: user.email }, c.env.JWT_SECRET);
  return c.json({ token, role: 'user', email: user.email });
});

// 3. 获取资源列表
app.get('/resources', async (c) => {
  const list = await c.env.DB.prepare('SELECT id, title, requires_login, view_limit, created_at FROM resources ORDER BY id DESC').all();
  return c.json(list.results);
});

// 4. 获取内容 (权限控制)
app.get('/resource/:id', async (c) => {
  const id = c.req.param('id');
  const token = c.req.header('Authorization')?.split(' ')[1];
  let user = null;
  if (token) user = await verifyToken(token, c.env.JWT_SECRET);

  const resource = await c.env.DB.prepare('SELECT * FROM resources WHERE id = ?').bind(id).first();
  if (!resource) return c.json({ error: '资源不存在' }, 404);

  if (resource.requires_login === 0) return c.json({ content: resource.content });

  if (!user) return c.json({ error: '请先登录' }, 401);

  if (resource.view_limit > 0 && user.role !== 'admin') {
    const view = await c.env.DB.prepare('SELECT count FROM views WHERE user_id = ? AND resource_id = ?').bind(user.id, id).first();
    const count = view ? view.count : 0;
    if (count >= resource.view_limit) return c.json({ error: `次数已用尽 (${resource.view_limit}次)` }, 403);

    if (count === 0) {
      await c.env.DB.prepare('INSERT INTO views (user_id, resource_id, count) VALUES (?, ?, 1)').bind(user.id, id).run();
    } else {
      await c.env.DB.prepare('UPDATE views SET count = count + 1 WHERE user_id = ? AND resource_id = ?').bind(user.id, id).run();
    }
  }

  return c.json({ content: resource.content });
});

// 5. 发布 (仅管理员)
app.post('/admin/create', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await verifyToken(token, c.env.JWT_SECRET);
  if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

  const { title, content, requires_login, view_limit } = await c.req.json();
  await c.env.DB.prepare(
    'INSERT INTO resources (title, content, requires_login, view_limit) VALUES (?, ?, ?, ?)'
  ).bind(title, content, requires_login ? 1 : 0, view_limit || 0).run();

  return c.json({ success: true });
});

export const onRequest = handle(app);
