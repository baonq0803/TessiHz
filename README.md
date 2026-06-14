# 🎵 TessiHz — Phòng nghe nhạc chung

Nghe nhạc YouTube cùng bạn bè, thời gian thực. Tạo phòng, mời bạn bè, cùng nghe và trò chuyện.

## ✨ Tính năng

- 🎵 **Phát nhạc đồng bộ** — cả phòng nghe cùng 1 bài, cùng 1 thời điểm
- 💬 **Chat thời gian thực** — trò chuyện khi nghe nhạc
- 📋 **Hàng đợi nhạc** — thêm bài, kéo thả sắp xếp, auto-play
- 🔒 **Phòng riêng tư** — tạo phòng có mật khẩu, chỉ người có mật khẩu mới vào được
- 👢 **Kick / 🔨 Ban** — chủ phòng quản lý người tham gia
- 🔑 **Quên mật khẩu** — reset password qua token
- 💪 **Password strength** — enforce mật khẩu mạnh khi đăng ký

## 🚀 Cài đặt

### Yêu cầu

- Node.js >= 18
- npm

### Cài đặt nhanh

```bash
git clone <repo-url>
cd phong-nghe-nhac
npm install
```

### Cấu hình

```bash
cp .env.example .env
```

Sửa `.env`:
```env
PORT=3000
NODE_ENV=development
SESSION_SECRET=change-me-to-random-string-32-chars-min
ALLOWED_ORIGINS=http://localhost:3000
```

### Chạy

```bash
npm start
```

Mở http://localhost:3000

## 🐳 Chạy với Docker

```bash
docker-compose up -d
```

## 📁 Cấu trúc project

```
├── server/
│   ├── index.js       # Server chính (Express + Socket.IO)
│   ├── db.js          # SQLite database layer
│   ├── tessihz.db     # SQLite database (auto-created)
│   └── data.json.backup  # Backup từ migration
├── public/
│   ├── index.html     # Landing page + login/register
│   ├── app.html       # Trang chính (danh sách phòng)
│   ├── room.html      # Trang phòng nhạc
│   ├── reset-password.html  # Reset password
│   ├── styles.css     # Design system + animations
│   └── images/        # Video backgrounds, logo
├── Dockerfile
├── docker-compose.yml
├── nginx-tessihz.conf
├── .env.example
├── .gitignore
└── package.json
```

## 🔧 API Endpoints

### Auth
| Method | Path | Mô tả |
|--------|------|-------|
| POST | `/api/register` | Đăng ký |
| POST | `/api/login` | Đăng nhập |
| POST | `/api/logout` | Đăng xuất |
| GET | `/api/me` | Kiểm tra trạng thái đăng nhập |

### Password Reset
| Method | Path | Mô tả |
|--------|------|-------|
| POST | `/api/forgot-password` | Yêu cầu reset password |
| POST | `/api/reset-password` | Đặt lại password bằng token |

### Profile
| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/api/profile` | Lấy thông tin profile |
| POST | `/api/profile` | Cập nhật displayName |

### Rooms
| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/api/rooms` | Danh sách tất cả phòng |
| POST | `/api/rooms` | Tạo phòng mới |
| GET | `/api/my-rooms` | Danh sách phòng của tôi |
| POST | `/api/room/:id/access` | Vào phòng riêng (nhập mật khẩu) |
| POST | `/api/room/:id/password` | Đổi mật khẩu phòng (chủ phòng) |
| POST | `/api/room/:id/kick` | Kick user (chủ phòng) |
| POST | `/api/room/:id/ban` | Ban user (chủ phòng) |
| POST | `/api/room/:id/unban` | Unban user (chủ phòng) |

### Other
| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/api/video-title` | Lấy tên video YouTube |
| GET | `/api/health` | Health check |

## 🔌 Socket.IO Events

### Client → Server
| Event | Data | Mô tả |
|-------|------|-------|
| `join-room` | `{ roomId, username }` | Vào phòng |
| `send-message` | `{ roomId, message }` | Gửi tin nhắn |
| `play-video` | `{ roomId, videoId }` | Phát video |
| `toggle-play` | `{ roomId, playing, currentTime }` | Play/pause |
| `add-to-queue` | `{ roomId, video }` | Thêm vào hàng đợi |
| `skip-video` | `{ roomId }` | Bài tiếp theo |
| `prev-video` | `{ roomId }` | Bài trước |
| `play-from-queue` | `{ roomId, videoId }` | Phát từ hàng đợi |
| `delete-from-queue` | `{ roomId, videoId }` | Xóa khỏi hàng đợi |
| `reorder-queue` | `{ roomId, fromId, toId }` | Sắp xếp lại hàng đợi |

### Server → Client
| Event | Data | Mô tả |
|-------|------|-------|
| `room-info` | `{ videoId, playing, currentTime, users, queue, isOwner }` | Thông tin phòng khi vừa vào |
| `user-joined` | `{ id, name }` | Có người mới vào |
| `user-left` | `{ id, name }` | Có người rời |
| `user-list` | `[{ id, name }]` | Danh sách user online |
| `new-message` | `{ user, message, time }` | Tin nhắn mới |
| `video-changed` | `{ videoId, playing }` | Video thay đổi |
| `play-toggled` | `{ playing, currentTime }` | Play/pause thay đổi |
| `queue-updated` | `[{ id, title, addedBy }]` | Hàng đợi thay đổi |
| `user-kicked` | `{ userId }` | Bị kick |
| `banned-from-room` | `{ message }` | Bị ban |

## 🔐 Bảo mật

- Session cookie: `httpOnly`, `sameSite: lax`, `secure` tự động theo môi trường
- Password: bcrypt hash (10 rounds)
- Rate limiting: 5 lần thử login/register/15ph, 60 API calls/phút
- Input validation: sanitize HTML, giới hạn độ dài, whitelist ký tự
- XSS prevention: escape HTML trước khi render chat
- CORS: chỉ cho ph origins được config

## 📝 License

MIT
