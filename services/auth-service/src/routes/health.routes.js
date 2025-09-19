const express = require('express');
const router = express.Router();

router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'UP',
    service: 'Auth Service',
    timestamp: new Date().toISOString()
  });
});

router.get('/ready', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'READY',
    service: 'Auth Service',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;