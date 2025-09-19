const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const User = require('../models/user.model');

const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const jwtSecret = process.env.JWT_SECRET || 'change-me';
const jwtExpires = process.env.JWT_EXPIRE || '24h';
const jwtCookieExpire = parseInt(process.env.JWT_COOKIE_EXPIRE || '1', 10); // in days

// Generate JWT token
const generateToken = (user) => {
  const payload = process.env.DB_TYPE === 'mongodb'
    ? { id: user._id }
    : { id: user.id, email: user.email, role: user.role };

  return jwt.sign(payload, jwtSecret, { expiresIn: jwtExpires });
};

// Send token response with cookie
const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user);

  const options = {
    expires: new Date(Date.now() + jwtCookieExpire * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') options.secure = true;

  res.status(statusCode).cookie('token', token, options).json({
    success: true,
    token,
    data: process.env.DB_TYPE === 'mongodb'
      ? { id: user._id, username: user.username, email: user.email, role: user.role }
      : { id: user.id, name: user.name, email: user.email, role: user.role }
  });
};

// Register user
exports.register = async (req, res, next) => {
  try {
    const { username, name, email, password, role } = req.body;

    let user;
    if (process.env.DB_TYPE === 'mongodb') {
      user = await User.create({ username, email, password, role });
    } else {
      if (!name || !email || !password) return res.status(400).json({ message: 'Missing required fields' });
      const existing = await User.findOne({ where: { email } });
      if (existing) return res.status(409).json({ message: 'Email already in use' });
      const hash = await bcrypt.hash(password, saltRounds);
      user = await User.create({ name, email, password: hash, role });
    }

    sendTokenResponse(user, 201, res);
  } catch (err) {
    logger.error(err);
    next(err);
  }
};

// Login user
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing email or password' });

    let user, match;
    if (process.env.DB_TYPE === 'mongodb') {
      user = await User.findOne({ email }).select('+password');
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      match = await user.comparePassword(password);
    } else {
      user = await User.findOne({ where: { email } });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      match = await bcrypt.compare(password, user.password);
    }

    if (!match) return res.status(401).json({ message: 'Invalid credentials' });
    sendTokenResponse(user, 200, res);
  } catch (err) {
    logger.error(err);
    next(err);
  }
};

// Get current logged in user
exports.getMe = async (req, res, next) => {
  try {
    let user;
    if (process.env.DB_TYPE === 'mongodb') {
      user = await User.findById(req.user.id);
    } else {
      user = await User.findByPk(req.user.id, { attributes: ['id', 'name', 'email', 'role', 'createdAt'] });
    }

    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    logger.error(err);
    next(err);
  }
};

// Logout user
exports.logout = async (req, res, next) => {
  try {
    res.cookie('token', 'none', { expires: new Date(Date.now() + 10 * 1000), httpOnly: true });
    res.status(200).json({ success: true, message: 'User logged out successfully' });
  } catch (err) {
    logger.error(err);
    next(err);
  }
};

// Update user details
exports.updateDetails = async (req, res, next) => {
  try {
    let updatedUser;
    if (process.env.DB_TYPE === 'mongodb') {
      const fieldsToUpdate = { username: req.body.username, email: req.body.email };
      updatedUser = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, { new: true, runValidators: true });
    } else {
      const { name, email } = req.body;
      updatedUser = await User.update({ name, email }, { where: { id: req.user.id }, returning: true });
      updatedUser = updatedUser[1][0]; // Sequelize returns [affectedCount, [rows]]
    }

    res.status(200).json({ success: true, data: updatedUser });
  } catch (err) {
    logger.error(err);
    next(err);
  }
};

// Update password
exports.updatePassword = async (req, res, next) => {
  try {
    let user, isMatch;
    const { currentPassword, newPassword } = req.body;

    if (process.env.DB_TYPE === 'mongodb') {
      user = await User.findById(req.user.id).select('+password');
      isMatch = await user.comparePassword(currentPassword);
      if (!isMatch) return res.status(401).json({ message: 'Password is incorrect' });
      user.password = newPassword;
      await user.save();
    } else {
      user = await User.findByPk(req.user.id);
      isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) return res.status(401).json({ message: 'Password is incorrect' });
      const hash = await bcrypt.hash(newPassword, saltRounds);
      await User.update({ password: hash }, { where: { id: req.user.id } });
    }

    sendTokenResponse(user, 200, res);
  } catch (err) {
    logger.error(err);
    next(err);
  }
};