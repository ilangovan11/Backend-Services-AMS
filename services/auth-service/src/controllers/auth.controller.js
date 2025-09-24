const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const User = require('../models/user.model');

const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const jwtSecret = process.env.JWT_SECRET || 'change-me';
const jwtExpires = process.env.JWT_EXPIRE || '24h';
const jwtCookieExpire = parseInt(process.env.JWT_COOKIE_EXPIRE || '1', 10);

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    jwtSecret,
    { expiresIn: jwtExpires }
  );
};

// Send token response with cookie
const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user);
  const options = {
    expires: new Date(Date.now() + jwtCookieExpire * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === 'production') options.secure = true;

  res.status(statusCode).json({
    success: true,
    token,
    user: { id: user.id, name: user.name || user.username, email: user.email, role: user.role },
  });
};

// Register user
const register = async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing required fields' });

    const existing = await User.findOne({ where: { email: email.toLowerCase() } });
    if (existing) return res.status(409).json({ message: 'Email already in use' });

    const hash = await bcrypt.hash(password, saltRounds);
    const user = await User.create({ name, email: email.toLowerCase(), password: hash, role: role || 'user' });

    sendTokenResponse(user, 201, res);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Registration failed. Please try again later.' });
  }
};

// Login user
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing email or password' });

    const user = await User.findOne({ where: { email: email.toLowerCase() } });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    sendTokenResponse(user, 200, res);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Login failed. Please try again later.' });
  }
};

// Get current logged in user
const getMe = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.user.id, { attributes: ['id', 'name', 'email', 'role', 'createdAt'] });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Failed to fetch user' });
  }
};

// Logout user
const logout = async (req, res, next) => {
  try {
    res.cookie('token', 'none', { expires: new Date(Date.now() + 10 * 1000), httpOnly: true });
    res.status(200).json({ success: true, message: 'User logged out successfully' });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Logout failed' });
  }
};

// Update user details
const updateDetails = async (req, res, next) => {
  try {
    const { name, email } = req.body;
    const [rows, [updatedUser]] = await User.update(
      { name, email: email.toLowerCase() },
      { where: { id: req.user.id }, returning: true }
    );
    res.status(200).json({ success: true, data: updatedUser });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Failed to update user details' });
  }
};

// Update password
const updatePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findByPk(req.user.id);
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(401).json({ message: 'Password is incorrect' });

    const hash = await bcrypt.hash(newPassword, saltRounds);
    await User.update({ password: hash }, { where: { id: req.user.id } });
    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: 'Failed to update password' });
  }
};

module.exports = { register, login, getMe, logout, updateDetails, updatePassword };