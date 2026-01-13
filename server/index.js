require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http'); // <--- 1. Import HTTP
const { Server } = require("socket.io");
const authRoute = require('./routes/auth');
const usersRoute = require('./routes/users');
const secretsRoute = require('./routes/secrets');

const app = express();

app.use(express.json());
app.use(cors());
// --- 3. CẤU HÌNH SOCKET.IO ---
const server = http.createServer(app); // Tạo server bọc lấy app
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173", // URL của React Frontend
    methods: ["GET", "POST", "PUT"]
  }
});

// Lắng nghe kết nối
io.on("connection", (socket) => {
  console.log(`🔌 Có người kết nối: ${socket.id}`);

  // Khi Client gửi sự kiện 'join_room' (kèm userId), cho họ vào phòng riêng
  socket.on("join_room", (userId) => {
    socket.join(userId);
    console.log(`User ${userId} đã vào phòng riêng.`);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected", socket.id);
  });
});

// Middleware để truyền biến 'io' xuống các Routes
app.use((req, res, next) => {
  req.io = io; // Gán io vào req
  next();
});
// Kết nối DB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/secret_manager')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log(err));

// Sử dụng Route Auth
app.use('/api/auth', authRoute);
app.use('/api/users', usersRoute);  
app.use('/api/secrets', secretsRoute);
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));