const express = require('express');
const router = express.Router();
const {
  register,
  login,
  getMe,
  logout,
  updateDetails,
  updatePassword
} = require('../controllers/auth.controller');
const { authenticate, authorize } = require('../middlewares/auth.middleware');

// Public routes
router.post('/register', register);
router.post('/login', login);

// Private routes (authenticated)
router.get('/me', authenticate, getMe);
router.get('/logout', authenticate, logout);
router.put('/updatedetails', authenticate, updateDetails);
router.put('/updatepassword', authenticate, updatePassword);

// Admin only routes example (uncomment when needed)
// router.get('/admin/users', authenticate, authorize('admin'), getUsers);

module.exports = router;
