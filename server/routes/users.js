const express = require('express');
const router = express.Router();
const User = require('../models/User');

// GET /api/users - Lấy danh sách user để share
router.get('/', async (req, res) => {
  try {
    // Chỉ lấy _id, email và public_key. KHÔNG lấy salt/auth_hash
    const users = await User.find({}, 'email public_key');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Lỗi Server" });
  }
});

module.exports = router;