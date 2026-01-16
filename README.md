# 🔐 TeamVault - Team Secret Manager

**Zero-Knowledge Team Secret Management Platform** với client-side encryption, RBAC, và audit logging.

## 🌟 Tính năng chính

### ✨ Bảo mật Zero-Knowledge
- **Client-side Encryption**: Tất cả mã hóa/giải mã diễn ra trên trình duyệt
- **Hybrid Encryption**: AES-256 (symmetric) + ECDH P-384 (asymmetric)
- **Master Password**: Private key được mã hóa bằng PBKDF2 (100,000 iterations)
- **Key Wrapping**: Chia sẻ an toàn bằng ECDH + HKDF

### 👥 Quản lý Team
- **Role-Based Access Control (RBAC)**:
  - **Owner**: Full quyền (read, edit, share, delete)
  - **Editor**: Read & Edit (không share/delete)
  - **Viewer**: Chỉ xem
- **Temporary Access**: Cấp quyền truy cập có thời hạn
- **Real-time Notifications**: Socket.IO cho thông báo ngay lập tức

### 📊 Audit & Compliance
- **Full Audit Logging**: Track tất cả actions (create, view, share, delete)
- **Activity History**: Xem lịch sử hoạt động theo user/secret
- **IP & User Agent Tracking**: Ghi nhận thông tin truy cập

### 🔒 Bảo mật nâng cao
- **Data Integrity**: SHA-256 checksum chống rollback attack
- **Secret Versioning**: Theo dõi phiên bản và changes
- **Secret Expiration**: Tự động expire và xóa secrets
- **Password Generator**: Tạo password mạnh với crypto.getRandomValues

### 🎨 UX/UI
- **Secret Strength Indicator**: Đánh giá độ mạnh password real-time
- **Search & Filter**: Tìm kiếm và lọc theo category
- **Pagination**: Xử lý hiệu quả khi có nhiều secrets

## 🏗️ Kiến trúc

```
┌─────────────────────────────────────────────┐
│           Client (React + Vite)             │
│  - Web Crypto API                           │
│  - Zero-Knowledge Encryption                │
│  - ECDH, AES-GCM, PBKDF2, HKDF             │
└────────────────┬────────────────────────────┘
                 │ HTTPS (encrypted data only)
                 ▼
┌─────────────────────────────────────────────┐
│         Server (Node.js + Express)          │
│  - REST API                                 │
│  - Socket.IO (real-time)                    │
│  - Audit Logging                            │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│            MongoDB Database                 │
│  - Encrypted secrets (ciphertext)           │
│  - Wrapped keys                             │
│  - Audit logs                               │
└─────────────────────────────────────────────┘
```

## 🚀 Cài đặt và chạy

### Yêu cầu
- Node.js v18+
- MongoDB v5.0+
- npm hoặc yarn

### Server
```bash
cd mmud/server
npm install

# Tạo file .env
echo 'PORT=5000' > .env
echo 'MONGO_URI=mongodb://localhost:27017/teamvault' >> .env

npm run dev
```

### Client
```bash
cd mmud/client
npm install
npm run dev
```

Mở trình duyệt: `http://localhost:5173`

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - Đăng ký user mới
- `GET /api/auth/salt/:email` - Lấy salt cho login
- `POST /api/auth/login` - Đăng nhập

### Secrets
- `POST /api/secrets` - Tạo secret mới
- `GET /api/secrets/:email` - Lấy danh sách secrets
- `PUT /api/secrets/:id` - Cập nhật secret
- `DELETE /api/secrets/:id` - Xóa secret
- `PUT /api/secrets/share` - Chia sẻ secret

### Audit Logs
- `GET /api/audit-logs` - Lấy audit logs (với filters)
- `GET /api/audit-logs/secret/:secretId` - Logs của secret
- `GET /api/audit-logs/user/:userId` - Logs của user

### Users
- `GET /api/users` - Lấy danh sách users

## 🔐 Flow mã hóa

### Đăng ký (Registration)
```
1. Client: Password + Salt → Master Key (PBKDF2)
2. Client: Master Key → Auth Hash (SHA-256)
3. Client: Generate ECDH key pair (Public + Private)
4. Client: Master Key + Private Key → Encrypted Private Key (AES-GCM)
5. Client → Server: Auth Hash, Public Key, Encrypted Private Key, Salt
6. Server: Lưu vào MongoDB
```

### Tạo Secret
```
1. Client: Generate random AES key K
2. Client: K + Secret plaintext → Encrypted Secret (AES-GCM)
3. Client: Generate ephemeral ECDH key pair
4. Client: Ephemeral Priv + Owner Pub → Shared Secret (ECDH)
5. Client: Shared Secret → Wrapping Key (HKDF)
6. Client: Wrapping Key + K → Wrapped K (AES-GCM)
7. Client → Server: Encrypted Secret + Wrapped K + Ephemeral Pub
8. Server: Calculate checksum, save to MongoDB
```

### Chia sẻ Secret
```
1. Client A: Unwrap K using own private key
2. Client A: Get Public Key của recipient B
3. Client A: Generate new ephemeral key pair
4. Client A: Ephemeral Priv + B Pub → Shared Secret
5. Client A: Re-wrap K for B
6. Client A → Server: New wrapped K for B + role + permissions
7. Server: Update access_list, emit Socket.IO notification to B
```

## 📦 Dependencies

### Server
- `express` - Web framework
- `mongoose` - MongoDB ODM
- `socket.io` - Real-time communication
- `cors` - CORS middleware
- `dotenv` - Environment variables

### Client
- `react` - UI library
- `react-router-dom` - Routing
- `axios` - HTTP client
- `socket.io-client` - WebSocket client
- `lucide-react` - Icons
- `vite` - Build tool

## 🛡️ Security Best Practices

1. **Never store plaintext secrets** - Server chỉ lưu ciphertext
2. **Master key stays in memory** - Không lưu vào localStorage
3. **Use strong KDF** - PBKDF2 với 100,000 iterations
4. **Implement checksum** - Chống tampering và rollback
5. **Audit everything** - Log tất cả access và modifications
6. **Use RBAC** - Phân quyền rõ ràng
7. **Set expiration** - Secrets có thể tự động expire

## 📈 Cải tiến tương lai

- [ ] Multi-Factor Authentication (MFA)
- [ ] Zero-Knowledge Password Reset
- [ ] IndexedDB cache cho offline support
- [ ] Web Worker cho crypto operations
- [ ] File encryption support
- [ ] Secret templates
- [ ] Advanced analytics dashboard

## 👨‍💻 Tác giả

Team Secret Manager - MMUD Project

## 📄 License

MIT License
