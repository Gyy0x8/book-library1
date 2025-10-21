// server.js
const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const urlLib = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// 环境变量（在 Vercel 或本地设置）
// MONGO_URI - MongoDB Atlas 连接字符串
// JWT_SECRET - 用于签发 JWT
// API_KEY - 如果你还用第三方小说API（可选）
const MONGO_URI = process.env.MONGO_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_a_strong_secret';
const API_KEY = process.env.API_KEY || 'a14b5cdff147b1262882db2ca29355bd';
const BASE_URL = 'https://api.xcvts.cn/api/xiaoshuo/axdzs';

// ---------- MongoDB 连接与模型 ----------
if (!MONGO_URI) {
  console.warn('⚠️ MONGO_URI 未设置，用户注册/登录会失败（请在本地或 Vercel 环境变量设置 MONGO_URI）');
} else {
  mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ 已连接到 MongoDB Atlas'))
    .catch(err => console.error('❌ 连接 MongoDB 失败：', err));
}

// 定义用户模型
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }, // 存储哈希
}, { timestamps: true });

let User;
try {
  User = mongoose.model('User') || mongoose.model('User', userSchema);
} catch (e) {
  User = mongoose.model('User', userSchema);
}

// ---------- 中间件 ----------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- 工具：向第三方 API 发起请求（JSON） ----------
function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https://') ? https : http;
    client.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (err) {
          reject(new Error('解析 JSON 失败: ' + err.message));
        }
      });
    }).on('error', (err) => {
      reject(new Error('请求失败: ' + err.message));
    });
  });
}

// ---------- 注册接口 ----------
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '缺少用户名或密码' });

    const existing = await User.findOne({ username }).exec();
    if (existing) return res.status(400).json({ error: '用户已存在' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed });
    await user.save();
    res.json({ message: '注册成功' });
  } catch (err) {
    console.error('注册错误：', err);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ---------- 登录接口 ----------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '缺少用户名或密码' });

    const user = await User.findOne({ username }).exec();
    if (!user) return res.status(400).json({ error: '用户不存在或密码错误' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: '用户不存在或密码错误' });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '4h' });
    res.json({ message: '登录成功', token });
  } catch (err) {
    console.error('登录错误：', err);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ---------- 验证中间件 ----------
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: '未提供令牌' });
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: '无效或过期的令牌' });
    req.user = payload;
    next();
  });
}

// ---------- 搜索代理（保留你原有逻辑） ----------
app.get('/api/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) return res.status(400).json({ error: '缺少查询参数 q' });

    const apiUrl = `${BASE_URL}?apiKey=${API_KEY}&q=${encodeURIComponent(query)}`;
    console.log('请求外部 API:', apiUrl);
    const data = await makeRequest(apiUrl);
    res.json(data);
  } catch (err) {
    console.error('搜索代理错误：', err);
    res.status(500).json({ error: '服务器内部错误: ' + err.message });
  }
});

// ---------- 受保护的下载代理 ----------
/**
 * GET /api/download?url=<encoded_url>&filename=<optional>
 * - 需要 Authorization: Bearer <token>
 * - 后端去请求目标 URL，并把响应流转发回浏览器（带 attachment header）
 */
app.get('/api/download', authenticate, async (req, res) => {
  try {
    const targetUrl = req.query.url;
    const suggestedName = req.query.filename || 'novel.zip';

    if (!targetUrl) return res.status(400).json({ error: '缺少 url 参数' });

    // 解析目标 URL，选择 http/https 客户端
    const parsed = urlLib.parse(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    console.log(`[下载代理] 用户 ${req.user.username} 请求下载:`, targetUrl);

    const requestOptions = {
      headers: {
        // 某些网站要求伪装UA
        'User-Agent': 'Mozilla/5.0 (Node.js) NovelDownloader/1.0',
        // 可按需添加 Referer 或 Cookie
      }
    };

    client.get(targetUrl, requestOptions, (proxyRes) => {
      if (proxyRes.statusCode >= 400) {
        return res.status(502).json({ error: `目标站点返回错误: ${proxyRes.statusCode}` });
      }

      // 尝试取目标响应的文件名
      let filename = suggestedName;
      const cd = proxyRes.headers['content-disposition'];
      if (cd) {
        const m = cd.match(/filename="?([^"]+)"?/);
        if (m) filename = m[1];
      } else {
        // 若目标响应没有文件名，用路径最后一段作为文件名
        const parts = parsed.pathname ? parsed.pathname.split('/') : [];
        const last = parts[parts.length - 1] || '';
        if (last.includes('.')) filename = last;
      }

      // 设置下载头（强制 attachment）
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
      if (proxyRes.headers['content-type']) {
        res.setHeader('Content-Type', proxyRes.headers['content-type']);
      } else {
        res.setHeader('Content-Type', 'application/octet-stream');
      }

      // 将目标服务器的响应流管道到客户端响应（stream）
      proxyRes.pipe(res);
    }).on('error', (err) => {
      console.error('代理下载错误：', err);
      res.status(500).json({ error: '代理下载失败: ' + err.message });
    });

  } catch (err) {
    console.error('下载接口错误：', err);
    res.status(500).json({ error: '下载失败: ' + err.message });
  }
});

// ---------- 提供静态文件（前端页面） ----------
app.use(express.static(path.join(__dirname)));

// 首页路由
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 只在本地/dev 环境启动监听（Vercel 会直接调用 exported app）
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`🚀 服务器运行在 http://localhost:${PORT}`);
    console.log(`🔍 搜索接口: http://localhost:${PORT}/api/search?q=小说名称`);
    console.log(`📥 下载接口(需要登录): http://localhost:${PORT}/api/download?url=<目标url>&filename=name.zip`);
    console.log('📦 注册: POST /api/register  登录: POST /api/login');
  });
}

module.exports = app;
