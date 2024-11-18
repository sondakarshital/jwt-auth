const jwt = require('jsonwebtoken');
const client = require('./redisClient');

// Generate Access Token
function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: '15m',
  });
}

// Generate Refresh Token
function generateRefreshToken(payload) {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: '7d',
  });
}

// Blocklist Access Token
async function blocklistAccessToken(token) {
  const decoded = jwt.decode(token);
  const expiry = decoded.exp * 1000; // Expiration time in ms
  await client.setEx(
    `blocklist:${token}`,
    Math.ceil((expiry - Date.now()) / 1000),
    'true'
  );
}

// Check if Access Token is Blocklisted
async function isAccessTokenBlocklisted(token) {
  return await client.get(`blocklist:${token}`);
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  blocklistAccessToken,
  isAccessTokenBlocklisted,
};
