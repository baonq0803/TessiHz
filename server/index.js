// ============================================
//  TessiHz — SERVER (v3.3 — Stable)
// ============================================

require('dotenv').config();

const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const session = require('cookie-session');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const dbLayer = require('./db');

// --- Config ---
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'phong-nghe-nhac-secret-key-2024';
const NODE_ENV = process.env.NODE_ENV || 'development';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://localhost:3001'];

// --- Sanitization & Validation ---
function sanitize(str, maxLen = 100) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().replace(/[<>]/g, '').slice(0, maxLen);
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return null;
  const cleaned = username.trim();
  if (cleaned.length < 2 || cleaned.length > 30) return null;
  if (!/^[a-zA-Z0-9_\sÀ-ỹ]+$/.test(cleaned)) return null;
  return cleaned;
}

function validateRoomName(name) {
  if (!name || typeof name !== 'string') return null;
  const cleaned = name.trim();
  if (cleaned.length < 2 || cleaned.length > 50) return null;
  if (!/^[a-zA-Z0-9_\sÀ-ỹ\-]+$/.test(cleaned)) return null;
  return cleaned;
}

function validateMessage(msg) {
  if (!msg || typeof msg !== 'string') return null;
  const cleaned = msg.trim();
  if (cleaned.length === 0 || cleaned.length > 1000) return null;
  return cleaned;
}

function checkPasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (score <= 2) return { ok: false, level: 'weak', message: 'Mật khẩu yếu — thêm chữ hoa, số, ký tự đặc biệt' };
  if (score <= 4) return { ok: true, level: 'medium', message: 'Mật khẩu tạm được' };
  return { ok: true, level: 'strong', message: 'Mật khẩu mạnh!' };
}

// --- Rate Limiters ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { ok: false, message: 'Quá nhiều lần thử! Vui lòng đợi 15 phút.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { ok: false, message: 'Quá nhiều yêu cầu! Vui lòng đợi một chút.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { ok: false, message: 'Quá nhiều yêu cầu reset! Vui lòng đợi 1 giờ.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Init ---
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    credentials: true,
  },
});

// --- Middleware ---
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, '../public')));

app.use(session({
  name: 'tessihz_session',
  keys: [SESSION_SECRET],
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: 'lax',
  domain: process.env.COOKIE_DOMAIN || undefined,
}));

// ============================================
//  AUTH MIDDLEWARE
// ============================================
function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  return res.json({ loggedIn: false });
}

// ============================================
//  ROUTES: XÁC THỰC
// ============================================

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password, displayName } = req.body;

    const validUsername = validateUsername(username);
    if (!validUsername) {
      return res.json({ ok: false, message: 'Tên đăng nhập phải từ 2-30 ký tự!' });
    }
    if (!password || password.length < 6) {
      return res.json({ ok: false, message: 'Mật khẩu phải có ít nhất 6 ký tự!' });
    }
    if (password.length > 128) {
      return res.json({ ok: false, message: 'Mật khẩu quá dài!' });
    }

    const strength = checkPasswordStrength(password);
    if (!strength.ok) {
      return res.json({ ok: false, message: strength.message });
    }

    const existing = dbLayer.findUserByUsername(validUsername);
    if (existing) {
      return res.json({ ok: false, message: 'Tên này đã có người dùng rồi!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatar = validUsername[0].toUpperCase();
    const now = new Date().toISOString();

    dbLayer.createUser({
      id: uuidv4(),
      username: validUsername,
      displayName: displayName ? sanitize(displayName, 50) : validUsername,
      password: hashedPassword,
      avatar,
      createdAt: now,
      resetToken: null,
      resetTokenExpiry: null,
    });

    const newUser = dbLayer.findUserByUsername(validUsername);
    req.session.userId = newUser.id;

    return res.json({
      ok: true,
      user: { id: newUser.id, username: newUser.username, displayName: newUser.displayName, avatar: newUser.avatar }
    });
  } catch (err) {
    console.error('Lỗi đăng ký:', err);
    return res.json({ ok: false, message: 'Có lỗi xảy ra!' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    const validUsername = validateUsername(username);
    if (!validUsername) {
      return res.json({ ok: false, message: 'Tên đăng nhập không hợp lệ!' });
    }
    if (!password) {
      return res.json({ ok: false, message: 'Nhập mật khẩu!' });
    }

    const user = dbLayer.findUserByUsername(validUsername);
    if (!user) {
      return res.json({ ok: false, message: 'Không tìm thấy tên này!' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.json({ ok: false, message: 'Mật khẩu sai rồi!' });
    }

    req.session.userId = user.id;

    return res.json({
      ok: true,
      user: { id: user.id, username: user.username, displayName: user.displayName, avatar: user.avatar }
    });
  } catch (err) {
    console.error('Lỗi đăng nhập:', err);
    return res.json({ ok: false, message: 'Có lỗi xảy ra!' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session = null;
  return res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = dbLayer.findUserById(req.session.userId);
  if (!user) return res.json({ loggedIn: false });

  return res.json({
    loggedIn: true,
    user: { id: user.id, username: user.username, displayName: user.displayName, avatar: user.avatar }
  });
});

// ============================================
//  PASSWORD RESET
// ============================================

app.post('/api/forgot-password', resetLimiter, (req, res) => {
  const { username } = req.body;
  const validUsername = validateUsername(username);
  if (!validUsername) {
    return res.json({ ok: false, message: 'Tên đăng nhập không hợp lệ!' });
  }

  const user = dbLayer.findUserByUsername(validUsername);

  if (!user) {
    return res.json({ ok: true, message: 'Nếu tên đăng nhập tồn tại, hướng dẫn reset đã được ghi nhận.' });
  }

  const resetToken = uuidv4();
  const expiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  dbLayer.setResetToken(user.id, resetToken, expiry);

  const resetUrl = `http://localhost:${PORT}/reset-password?token=${resetToken}`;
  console.log(`\n🔑 PASSWORD RESET cho "${user.username}": ${resetUrl}\n`);

  return res.json({
    ok: true,
    message: 'Nếu tên đăng nhập tồn tại, link reset đã được tạo.',
    ...(NODE_ENV !== 'production' && { _devToken: resetToken, _devUrl: resetUrl })
  });
});

app.post('/api/reset-password', resetLimiter, async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.json({ ok: false, message: 'Thiếu thông tin!' });
  }
  if (newPassword.length < 6) {
    return res.json({ ok: false, message: 'Mật khẩu mới phải có ít nhất 6 ký tự!' });
  }
  if (newPassword.length > 128) {
    return res.json({ ok: false, message: 'Mật khẩu quá dài!' });
  }

  const strength = checkPasswordStrength(newPassword);
  if (!strength.ok) {
    return res.json({ ok: false, message: strength.message });
  }

  const user = dbLayer.findUserByResetToken(token);
  if (!user) {
    return res.json({ ok: false, message: 'Token không hợp lệ!' });
  }

  if (user.resetTokenExpiry && new Date(user.resetTokenExpiry) < new Date()) {
    dbLayer.setResetToken(user.id, null, null);
    return res.json({ ok: false, message: 'Link reset đã hết hạn!' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  dbLayer.updatePassword(user.id, hashedPassword);

  return res.json({ ok: true, message: 'Đặt lại mật khẩu thành công!' });
});

// ============================================
//  ROUTES: HỒ SƠ NGƯỜI DÙNG
// ============================================

app.get('/api/profile', requireAuth, generalLimiter, (req, res) => {
  const user = dbLayer.findUserById(req.session.userId);
  if (!user) return res.json({ ok: false });

  const myRooms = dbLayer.getRoomsByOwner(user.id);
  return res.json({
    ok: true,
    user: { id: user.id, username: user.username, displayName: user.displayName, avatar: user.avatar },
    roomCount: myRooms.length,
    joinedAt: user.createdAt
  });
});

app.post('/api/profile', requireAuth, generalLimiter, (req, res) => {
  const { displayName } = req.body;
  const user = dbLayer.findUserById(req.session.userId);
  if (!user) return res.json({ ok: false, message: 'Không tìm thấy user!' });

  if (displayName !== undefined) {
    const cleaned = sanitize(displayName, 50);
    if (cleaned.length < 1) {
      return res.json({ ok: false, message: 'Tên hiển thị không hợp lệ!' });
    }
    dbLayer.updateProfile(user.id, cleaned);
  }

  const updated = dbLayer.findUserById(user.id);
  return res.json({
    ok: true,
    user: { id: updated.id, username: updated.username, displayName: updated.displayName, avatar: updated.avatar }
  });
});

// ============================================
//  ROUTES: PHÒNG
// ============================================

app.get('/api/rooms', requireAuth, generalLimiter, (req, res) => {
  const allRooms = dbLayer.getAllRooms();
  const allUsers = dbLayer.getAllUsers();
  const rooms = allRooms.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description || '',
    ownerName: allUsers.find(u => u.id === r.ownerId)?.displayName || 'Không rõ',
    isPrivate: r.isPrivate,
    createdAt: r.createdAt
  }));
  return res.json({ ok: true, rooms });
});

app.post('/api/rooms', requireAuth, generalLimiter, (req, res) => {
  const rawName = req.body.name;
  const name = validateRoomName(rawName);
  if (!name) {
    return res.json({ ok: false, message: 'Tên phòng phải từ 2-50 ký tự!' });
  }

  const description = sanitize(req.body.description || '', 200);
  const isPrivate = !!req.body.isPrivate;
  const roomPassword = req.body.password || '';

  if (isPrivate && !roomPassword) {
    return res.json({ ok: false, message: 'Phòng riêng tư cần có mật khẩu!' });
  }
  if (isPrivate && roomPassword.length < 4) {
    return res.json({ ok: false, message: 'Mật khẩu phòng phải có ít nhất 4 ký tự!' });
  }

  let roomId = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  if (!roomId) roomId = uuidv4().slice(0, 8);

  if (dbLayer.getRoomById(roomId)) {
    roomId = roomId + '-' + uuidv4().slice(0, 4);
  }

  dbLayer.createRoom({
    id: roomId,
    name,
    description,
    isPrivate,
    passwordHash: isPrivate ? bcrypt.hashSync(roomPassword, 10) : null,
    ownerId: req.session.userId,
    bannedUsers: [],
  });

  dbLayer.saveRoomState(roomId, { videoId: '', playing: false, currentTime: 0, queue: [] });

  return res.json({ ok: true, room: { id: roomId, name, description, isPrivate } });
});

app.get('/api/my-rooms', requireAuth, generalLimiter, (req, res) => {
  const myRooms = dbLayer.getRoomsByOwner(req.session.userId).map(r => ({
    id: r.id,
    name: r.name,
    description: r.description || '',
    isPrivate: r.isPrivate,
    createdAt: r.createdAt
  }));
  return res.json({ ok: true, rooms: myRooms });
});

// ============================================
//  PRIVATE ROOM ACCESS
// ============================================

app.post('/api/room/:roomId/access', requireAuth, generalLimiter, (req, res) => {
  const { roomId } = req.params;
  const { password } = req.body;

  const room = dbLayer.getRoomById(roomId);
  if (!room) {
    return res.json({ ok: false, message: 'Phòng không tồn tại!' });
  }

  if (!room.isPrivate) {
    return res.json({ ok: true, isPrivate: false });
  }

  if (!password) {
    return res.json({ ok: false, needsPassword: true, message: 'Phòng này cần mật khẩu để vào.' });
  }

  if (room.passwordHash && bcrypt.compareSync(password, room.passwordHash)) {
    return res.json({ ok: true, isPrivate: true });
  }

  return res.json({ ok: false, message: 'Mật khẩu phòng sai!' });
});

app.post('/api/room/:roomId/password', requireAuth, generalLimiter, (req, res) => {
  const { roomId } = req.params;
  const { newPassword } = req.body;

  const room = dbLayer.getRoomById(roomId);
  if (!room) return res.json({ ok: false, message: 'Phòng không tồn tại!' });
  if (room.ownerId !== req.session.userId) {
    return res.json({ ok: false, message: 'Chỉ chủ phòng mới đổi mật khẩu!' });
  }

  if (room.isPrivate) {
    if (!newPassword || newPassword.length < 4) {
      return res.json({ ok: false, message: 'Mật khẩu mới phải có ít nhất 4 ký tự!' });
    }
    dbLayer.updateRoomPassword(roomId, req.session.userId, bcrypt.hashSync(newPassword, 10));
  } else {
    dbLayer.updateRoomPassword(roomId, req.session.userId, null);
  }

  return res.json({ ok: true, message: 'Đã cập nhật mật khẩu phòng!' });
});

// ============================================
//  MODERATION: Kick & Ban
// ============================================

app.post('/api/room/:roomId/kick', requireAuth, generalLimiter, (req, res) => {
  const { roomId } = req.params;
  const { userId } = req.body;

  const room = dbLayer.getRoomById(roomId);
  if (!room) return res.json({ ok: false, message: 'Phòng không tồn tại!' });
  if (room.ownerId !== req.session.userId) {
    return res.json({ ok: false, message: 'Chỉ chủ phòng mới kick được người!' });
  }

  io.to(roomId).emit('user-kicked', { userId, reason: 'Bị chủ phòng kick' });

  if (rooms[roomId]) {
    const idx = rooms[roomId].users.findIndex(u => u.id === userId);
    if (idx !== -1) {
      const kicked = rooms[roomId].users[idx];
      rooms[roomId].users.splice(idx, 1);
      io.to(roomId).emit('user-left', kicked);
      io.to(roomId).emit('user-list', rooms[roomId].users);
    }
  }

  return res.json({ ok: true, message: 'Đã kick người dùng!' });
});

app.post('/api/room/:roomId/ban', requireAuth, generalLimiter, (req, res) => {
  const { roomId } = req.params;
  const { userId } = req.body;

  const room = dbLayer.getRoomById(roomId);
  if (!room) return res.json({ ok: false, message: 'Phòng không tồn tại!' });
  if (room.ownerId !== req.session.userId) {
    return res.json({ ok: false, message: 'Chỉ chủ phòng mới ban được người!' });
  }

  io.to(roomId).emit('user-kicked', { userId, reason: 'Bị chủ phòng ban' });
  if (rooms[roomId]) {
    const idx = rooms[roomId].users.findIndex(u => u.id === userId);
    if (idx !== -1) {
      rooms[roomId].users.splice(idx, 1);
      io.to(roomId).emit('user-list', rooms[roomId].users);
    }
  }

  const banned = [...(room.bannedUsers || [])];
  if (!banned.includes(userId)) {
    banned.push(userId);
    dbLayer.addBan(roomId, banned);
  }

  return res.json({ ok: true, message: 'Đã ban người dùng khỏi phòng!' });
});

app.post('/api/room/:roomId/unban', requireAuth, generalLimiter, (req, res) => {
  const { roomId } = req.params;
  const { userId } = req.body;

  const room = dbLayer.getRoomById(roomId);
  if (!room) return res.json({ ok: false, message: 'Phòng không tồn tại!' });
  if (room.ownerId !== req.session.userId) {
    return res.json({ ok: false, message: 'Chỉ chủ phòng mới unban được!' });
  }

  const banned = (room.bannedUsers || []).filter(id => id !== userId);
  dbLayer.addBan(roomId, banned);

  return res.json({ ok: true, message: 'Đã gỡ ban!' });
});

// ============================================
//  YOUTUBE + HTML PAGES
// ============================================

app.get('/api/video-title', generalLimiter, (req, res) => {
  const videoUrl = req.query.url;
  if (!videoUrl) return res.json({ ok: false, title: 'Unknown' });

  try { new URL(videoUrl); } catch {
    return res.json({ ok: false, title: 'Unknown' });
  }

  const oembedUrl = `https://www.youtube.com/oembed?url=${encodeURIComponent(videoUrl)}&format=json`;
  https.get(oembedUrl, { timeout: 5000 }, (youtubeRes) => {
    let data = '';
    youtubeRes.on('data', chunk => data += chunk);
    youtubeRes.on('end', () => {
      try {
        const info = JSON.parse(data);
        return res.json({ ok: true, title: info.title || 'Unknown' });
      } catch {
        return res.json({ ok: false, title: 'Unknown' });
      }
    });
  }).on('error', () => {
    return res.json({ ok: false, title: 'Unknown' });
  });
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/reset-password.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/app.html'));
});

app.get('/room/:roomId', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/room.html'));
});

// ============================================
//  SOCKET.IO
// ============================================
const rooms = {};
const socketEventCounts = new Map();

function getRoom(roomId) {
  if (!rooms[roomId]) {
    const room = { users: [], videoId: '', playing: false, currentTime: 0, queue: [] };
    const saved = dbLayer.getRoomState(roomId);
    if (saved) {
      room.videoId = saved.videoId;
      room.playing = saved.playing;
      room.currentTime = saved.currentTime;
      room.queue = saved.queue;
      console.log(`📦 Restored room "${roomId}": ${saved.queue.length} items in queue`);
    }
    rooms[roomId] = room;
  }
  return rooms[roomId];
}

function persistRoomState(roomId) {
  const room = rooms[roomId];
  if (!room) return;
  dbLayer.saveRoomState(roomId, {
    videoId: room.videoId,
    playing: room.playing,
    currentTime: room.currentTime,
    queue: room.queue,
  });
}

function checkSocketRateLimit(socketId) {
  const now = Date.now();
  const entry = socketEventCounts.get(socketId);
  if (!entry || now - entry.resetTime > 60000) {
    socketEventCounts.set(socketId, { count: 1, resetTime: now });
    return true;
  }
  entry.count++;
  return entry.count <= 60;
}

io.on('connection', (socket) => {
  console.log('📡 Kết nối:', socket.id);

  socket.on('join-room', ({ roomId, username }) => {
    if (!roomId || typeof roomId !== 'string' || roomId.length > 100) return;
    const safeUsername = validateUsername(username) || 'Người dùng';

    socket.join(roomId);
    const room = getRoom(roomId);
    const user = { id: socket.id, name: safeUsername };

    const persistentRoom = dbLayer.getRoomById(roomId);
    if (persistentRoom?.bannedUsers?.includes(user.id)) {
      socket.emit('banned-from-room', { message: 'Bạn đã bị ban khỏi phòng này!' });
      socket.leave(roomId);
      return;
    }

    room.users.push(user);

    socket.emit('room-info', {
      videoId: room.videoId, playing: room.playing,
      currentTime: room.currentTime, users: room.users, queue: room.queue,
      isOwner: persistentRoom?.ownerId === socket.id,
    });
    io.to(roomId).emit('user-joined', user);
    io.to(roomId).emit('user-list', room.users);
    console.log(`👤 ${user.name} vào phòng "${roomId}"`);
  });

  socket.on('send-message', ({ roomId, message }) => {
    if (!checkSocketRateLimit(socket.id)) {
      socket.emit('error', { message: 'Quá nhiều tin nhắn!' });
      return;
    }
    const user = findUser(socket.id, roomId);
    if (!user) return;

    const safeMsg = validateMessage(message);
    if (!safeMsg) return;

    io.to(roomId).emit('new-message', {
      user, message: safeMsg,
      time: new Date().toLocaleTimeString('vi', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('play-video', ({ roomId, videoId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    if (!videoId || typeof videoId !== 'string' || videoId.length > 20) return;
    const room = getRoom(roomId);
    room.videoId = videoId; room.playing = true;
    io.to(roomId).emit('video-changed', { videoId, playing: true, timestamp: Date.now() });
    persistRoomState(roomId);
  });

  socket.on('toggle-play', ({ roomId, playing, currentTime }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    const room = getRoom(roomId);
    room.playing = playing; room.currentTime = currentTime;
    io.to(roomId).emit('play-toggled', { playing, currentTime });
    persistRoomState(roomId);
  });

  socket.on('add-to-queue', ({ roomId, video }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    if (!video || !video.id) return;
    const safeTitle = sanitize(video.title || '', 200);
    const safeAddedBy = sanitize(video.addedBy || '', 50);
    const room = getRoom(roomId);
    room.queue.push({ id: video.id, title: safeTitle, addedBy: safeAddedBy });
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
  });

  socket.on('skip-video', ({ roomId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    const room = getRoom(roomId);
    if (room.queue.length === 0) return;
    const idx = room.queue.findIndex(v => v.id === room.videoId);
    const nextIdx = idx >= room.queue.length - 1 ? 0 : idx + 1;
    room.videoId = room.queue[nextIdx].id;
    room.playing = true;
    io.to(roomId).emit('video-changed', { videoId: room.videoId, playing: true, timestamp: Date.now() });
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
  });

  socket.on('prev-video', ({ roomId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    const room = getRoom(roomId);
    if (room.queue.length === 0) return;
    const idx = room.queue.findIndex(v => v.id === room.videoId);
    const prevIdx = idx <= 0 ? room.queue.length - 1 : idx - 1;
    room.videoId = room.queue[prevIdx].id;
    room.playing = true;
    io.to(roomId).emit('video-changed', { videoId: room.videoId, playing: true, timestamp: Date.now() });
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
  });

  socket.on('reorder-queue', ({ roomId, fromId, toId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    if (!fromId || !toId || fromId === toId) return;
    const room = getRoom(roomId);
    const fromIdx = room.queue.findIndex(v => v.id === fromId);
    const toIdx = room.queue.findIndex(v => v.id === toId);
    if (fromIdx === -1 || toIdx === -1) return;
    const [moved] = room.queue.splice(fromIdx, 1);
    room.queue.splice(toIdx, 0, moved);
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
  });

  socket.on('play-from-queue', ({ roomId, videoId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    if (!videoId) return;
    const room = getRoom(roomId);
    const idx = room.queue.findIndex(v => v.id === videoId);
    if (idx === -1) return;
    room.videoId = videoId;
    room.playing = true;
    io.to(roomId).emit('video-changed', { videoId, playing: true, timestamp: Date.now() });
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
  });

  socket.on('delete-from-queue', ({ roomId, videoId }) => {
    if (!checkSocketRateLimit(socket.id)) return;
    if (!videoId) return;
    const room = getRoom(roomId);
    const idx = room.queue.findIndex(v => v.id === videoId);
    if (idx === -1) return;
    const isPlaying = room.videoId === videoId;
    room.queue.splice(idx, 1);
    if (isPlaying && room.queue.length > 0) {
      room.videoId = room.queue[0].id;
      room.playing = true;
      io.to(roomId).emit('video-changed', { videoId: room.videoId, playing: true, timestamp: Date.now() });
    }
    io.to(roomId).emit('queue-updated', room.queue);
    persistRoomState(roomId);
    socket.emit('delete-confirmed', { deletedId: videoId, wasPlaying: isPlaying });
  });

  socket.on('disconnecting', () => {
    for (const roomId in rooms) {
      const room = rooms[roomId];
      const idx = room.users.findIndex(u => u.id === socket.id);
      if (idx !== -1) {
        const user = room.users[idx];
        room.users.splice(idx, 1);
        io.to(roomId).emit('user-left', user);
        io.to(roomId).emit('user-list', room.users);
        console.log(`👋 ${user.name} rời phòng "${roomId}"`);
        break;
      }
    }
  });

  socket.on('disconnect', () => {
    socketEventCounts.delete(socket.id);
    console.log('📡 Ngắt kết nối:', socket.id);
  });
});

function findUser(socketId, roomId) {
  return rooms[roomId]?.users.find(u => u.id === socketId) || null;
}

// ============================================
//  START
// ============================================
server.listen(PORT, () => {
  const userCount = dbLayer.getAllUsers().length;
  if (userCount === 0 && fs.existsSync(path.join(__dirname, 'data.json'))) {
    console.log('📦 Phát hiện data.json — đang migrate sang SQLite...');
    const ok = dbLayer.migrateFromJson();
    if (ok) {
      fs.renameSync(path.join(__dirname, 'data.json'), path.join(__dirname, 'data.json.backup'));
      console.log('✅ Migration xong! data.json → data.json.backup');
    }
  }

  console.log(`
  🎵 TessiHz v3.3 đã chạy! (${NODE_ENV})
  📍 Đăng nhập:     http://localhost:${PORT}/login
  📍 Trang chính:   http://localhost:${PORT}/app
  📌 Nhấn Ctrl+C để dừng
  `);
});
