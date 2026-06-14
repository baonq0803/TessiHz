// ============================================
//  TessiHz — Database Layer (SQLite via better-sqlite3)
// ============================================

const Database = require('better-sqlite3');
const path = require('path');
const { existsSync, readFileSync, unlinkSync } = require('fs');

const DB_PATH = path.join(__dirname, 'tessihz.db');
const DATA_FILE = path.join(__dirname, 'data.json');

// --- Init Database ---
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent reads
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// --- Create Tables ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    displayName     TEXT NOT NULL,
    password        TEXT NOT NULL,
    avatar          TEXT NOT NULL DEFAULT '?',
    createdAt       TEXT NOT NULL DEFAULT (datetime('now')),
    resetToken      TEXT,
    resetTokenExpiry TEXT
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    isPrivate       INTEGER NOT NULL DEFAULT 0,
    passwordHash    TEXT,
    ownerId         TEXT NOT NULL REFERENCES users(id),
    createdAt       TEXT NOT NULL DEFAULT (datetime('now')),
    bannedUsers     TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS room_state (
    roomId      TEXT PRIMARY KEY REFERENCES rooms(id),
    videoId     TEXT DEFAULT '',
    playing     INTEGER NOT NULL DEFAULT 0,
    currentTime REAL NOT NULL DEFAULT 0,
    queue       TEXT DEFAULT '[]',
    updatedAt   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_rooms_owner ON rooms(ownerId);
  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`);

// --- Prepared Statements ---
const stmts = {
  // User queries
  findUserById:       db.prepare('SELECT * FROM users WHERE id = ?'),
  findUserByUsername: db.prepare('SELECT * FROM users WHERE lower(username) = lower(?)'),
  insertUser:         db.prepare('INSERT INTO users (id, username, displayName, password, avatar, createdAt, resetToken, resetTokenExpiry) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'),
  updateUserPassword: db.prepare('UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?'),
  setResetToken:      db.prepare('UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE id = ?'),
  findUserByToken:    db.prepare('SELECT * FROM users WHERE resetToken = ?'),
  updateUserProfile:  db.prepare('UPDATE users SET displayName = ? WHERE id = ?'),
  allUsers:           db.prepare('SELECT id, username, displayName, avatar FROM users'),

  // Room queries
  getAllRooms:        db.prepare('SELECT * FROM rooms'),
  getRoomById:        db.prepare('SELECT * FROM rooms WHERE id = ?'),
  insertRoom:         db.prepare('INSERT INTO rooms (id, name, description, isPrivate, passwordHash, ownerId, bannedUsers) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  getRoomsByOwner:    db.prepare('SELECT id, name, description, isPrivate, createdAt FROM rooms WHERE ownerId = ?'),
  updateRoomPassword: db.prepare('UPDATE rooms SET passwordHash = ? WHERE id = ? AND ownerId = ?'),
  addBan:             db.prepare('UPDATE rooms SET bannedUsers = ? WHERE id = ?'),

  // Room state (persistent queue + video)
  getRoomState:    db.prepare('SELECT * FROM room_state WHERE roomId = ?'),
  upsertRoomState: db.prepare(`
    INSERT INTO room_state (roomId, videoId, playing, currentTime, queue, updatedAt)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(roomId) DO UPDATE SET
      videoId = excluded.videoId,
      playing = excluded.playing,
      currentTime = excluded.currentTime,
      queue = excluded.queue,
      updatedAt = excluded.updatedAt
  `),
  clearRoomState:  db.prepare('DELETE FROM room_state WHERE roomId = ?'),
};

// --- Transaction helpers ---
const insertUserTx = db.transaction((user) => {
  stmts.insertUser.run(user.id, user.username, user.displayName, user.password, user.avatar, user.createdAt, user.resetToken, user.resetTokenExpiry);
});

const insertRoomTx = db.transaction((room) => {
  stmts.insertRoom.run(room.id, room.name, room.description, room.isPrivate ? 1 : 0, room.passwordHash, room.ownerId, JSON.stringify(room.bannedUsers || []));
});

// ============================================
//  PUBLIC API
// ============================================

const dbLayer = {

  // --- Users ---
  findUserById(id) {
    return stmts.findUserById.get(id) || null;
  },

  findUserByUsername(username) {
    return stmts.findUserByUsername.get(username) || null;
  },

  createUser(user) {
    insertUserTx(user);
  },

  updatePassword(userId, hashedPassword) {
    stmts.updateUserPassword.run(hashedPassword, userId);
  },

  setResetToken(userId, token, expiry) {
    stmts.setResetToken.run(token, expiry, userId);
  },

  findUserByResetToken(token) {
    return stmts.findUserByToken.get(token) || null;
  },

  updateProfile(userId, displayName) {
    stmts.updateUserProfile.run(displayName, userId);
  },

  getAllUsers() {
    return stmts.allUsers.all();
  },

  // --- Rooms ---
  getAllRooms() {
    return stmts.getAllRooms.all().map(r => ({
      ...r,
      isPrivate: !!r.isPrivate,
      bannedUsers: JSON.parse(r.bannedUsers || '[]'),
    }));
  },

  getRoomById(id) {
    const r = stmts.getRoomById.get(id);
    if (!r) return null;
    return { ...r, isPrivate: !!r.isPrivate, bannedUsers: JSON.parse(r.bannedUsers || '[]') };
  },

  createRoom(room) {
    insertRoomTx(room);
  },

  getRoomsByOwner(ownerId) {
    return stmts.getRoomsByOwner.all(ownerId);
  },

  updateRoomPassword(roomId, ownerId, passwordHash) {
    return stmts.updateRoomPassword.run(passwordHash, roomId, ownerId);
  },

  addBan(roomId, bannedUsers) {
    stmts.addBan.run(JSON.stringify(bannedUsers), roomId);
  },

  // --- Room State (persistent queue + video) ---
  getRoomState(roomId) {
    const r = stmts.getRoomState.get(roomId);
    if (!r) return null;
    return {
      videoId: r.videoId || '',
      playing: !!r.playing,
      currentTime: r.currentTime || 0,
      queue: JSON.parse(r.queue || '[]'),
    };
  },

  saveRoomState(roomId, state) {
    stmts.upsertRoomState.run(
      roomId,
      state.videoId || '',
      state.playing ? 1 : 0,
      state.currentTime || 0,
      JSON.stringify(state.queue || []),
    );
  },

  clearRoomState(roomId) {
    stmts.clearRoomState.run(roomId);
  },

  // --- Migration from data.json ---
  migrateFromJson() {
    if (!existsSync(DATA_FILE)) return false;

    const data = JSON.parse(readFileSync(DATA_FILE, 'utf8'));

    const insertManyUsers = db.transaction((users) => {
      for (const u of users) {
        insertUserTx({
          id: u.id,
          username: u.username,
          displayName: u.displayName,
          password: u.password,
          avatar: u.avatar || '?',
          createdAt: u.createdAt || new Date().toISOString(),
          resetToken: u.resetToken || null,
          resetTokenExpiry: u.resetTokenExpiry || null,
        });
      }
    });

    const insertManyRooms = db.transaction((rooms) => {
      for (const r of rooms) {
        insertRoomTx({
          id: r.id,
          name: r.name,
          description: r.description || '',
          isPrivate: !!r.isPrivate,
          passwordHash: r.passwordHash || null,
          ownerId: r.ownerId,
          bannedUsers: r.bannedUsers || [],
        });
      }
    });

    try {
      insertManyUsers(data.users || []);
      insertManyRooms(data.rooms || []);
      console.log(`✅ Đã migrate ${(data.users || []).length} users, ${(data.rooms || []).length} rooms từ data.json → SQLite`);
      return true;
    } catch (err) {
      console.error('Lỗi migrate:', err.message);
      return false;
    }
  },
};

module.exports = dbLayer;
