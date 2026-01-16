const express = require('express');
const router = express.Router();
const AuditLog = require('../models/AuditLog');

// Middleware to extract IP and User Agent
function getClientInfo(req) {
  return {
    ip_address: req.ip || req.connection.remoteAddress,
    user_agent: req.get('user-agent')
  };
}

// Create audit log entry
async function logAction(data) {
  try {
    const log = new AuditLog(data);
    await log.save();
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
}

// GET /api/audit-logs - Get audit logs with filters
router.get('/', async (req, res) => {
  try {
    const { 
      user_id, 
      secret_id, 
      action, 
      start_date, 
      end_date, 
      limit = 50,
      page = 1 
    } = req.query;

    const query = {};
    if (user_id) query.user_id = user_id;
    if (secret_id) query.secret_id = secret_id;
    if (action) query.action = action;
    
    if (start_date || end_date) {
      query.timestamp = {};
      if (start_date) query.timestamp.$gte = new Date(start_date);
      if (end_date) query.timestamp.$lte = new Date(end_date);
    }

    const logs = await AuditLog.find(query)
      .populate('user_id', 'email')
      .populate('secret_id', 'name')
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await AuditLog.countDocuments(query);

    res.json({
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ message: 'Error fetching audit logs' });
  }
});

// GET /api/audit-logs/secret/:secretId - Get logs for specific secret
router.get('/secret/:secretId', async (req, res) => {
  try {
    const logs = await AuditLog.find({ secret_id: req.params.secretId })
      .populate('user_id', 'email')
      .sort({ timestamp: -1 })
      .limit(100);

    res.json(logs);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching secret logs' });
  }
});

// GET /api/audit-logs/user/:userId - Get logs for specific user
router.get('/user/:userId', async (req, res) => {
  try {
    const logs = await AuditLog.find({ user_id: req.params.userId })
      .populate('secret_id', 'name')
      .sort({ timestamp: -1 })
      .limit(100);

    res.json(logs);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user logs' });
  }
});

// Export helper function for use in other routes
router.logAction = logAction;
router.getClientInfo = getClientInfo;

module.exports = router;
