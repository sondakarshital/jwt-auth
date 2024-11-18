const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Hash passwords in production
  refreshTokens: [String], // Store valid refresh tokens
});

module.exports = mongoose.model('User', userSchema);
