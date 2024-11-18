require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const {
  generateAccessToken,
  generateRefreshToken,
  blocklistAccessToken,
  isAccessTokenBlocklisted,
} = require('./utils/jwtUtils');

const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// sign up user
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: 'Username and password are required' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: `${username} user created` });
  } catch (err) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }

  const accessToken = generateAccessToken({ username: user.username });
  const refreshToken = generateRefreshToken({ username: user.username });
  if (user?.refreshTokens?.length >= 3) user.refreshTokens.shift();
  user.refreshTokens.push(refreshToken);
  await user.save();

  res.json({ accessToken, refreshToken });
});

// Access Protected Route
app.get('/protected', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).send('Access token required');

  if (await isAccessTokenBlocklisted(token)) {
    return res.status(403).send('Token has been invalidated');
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid or expired token');
    res.json({ message: `Hello ${user.username}, welcome!` });
  });
});

// Refresh Token
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).send('Refresh token required');

  const user = await User.findOne({ refreshTokens: refreshToken });
  if (!user) return res.status(403).send('Invalid refresh token');

  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const newAccessToken = generateAccessToken({ username: payload.username });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).send('Invalid refresh token');
  }
});

// Logout
app.post('/logout', async (req, res) => {
  const { accessToken, refreshToken } = req.body;

  if (accessToken) {
    await blocklistAccessToken(accessToken);
  }

  if (refreshToken) {
    await User.updateOne(
      { refreshTokens: refreshToken },
      { $pull: { refreshTokens: refreshToken } }
    );
  }

  res.send('Logged out successfully');
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
