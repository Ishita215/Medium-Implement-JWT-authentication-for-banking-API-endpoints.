// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const verifyToken = require('./verifyToken');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Hardcoded demo user & account (demo only)
const demoUser = {
  id: 1,
  username: 'user1',
  password: 'password123' // plaintext only for demo
};

// In-memory account state (keyed by user id)
const accounts = {
  // starting balance $1000
  1: {
    balance: 1000
  }
};

// --- Login route ---
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  if (username !== demoUser.username || password !== demoUser.password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Create a token payload with user id and username
  const payload = { id: demoUser.id, username: demoUser.username };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

  return res.json({ token });
});

// --- Protected: get balance ---
app.get('/balance', verifyToken, (req, res) => {
  const uid = req.user && req.user.id;
  if (!uid || !accounts[uid]) {
    // Shouldn't happen in this demo, but safe-guard:
    return res.status(404).json({ message: 'Account not found' });
  }
  return res.json({ balance: accounts[uid].balance });
});

// --- Protected: deposit ---
app.post('/deposit', verifyToken, (req, res) => {
  const uid = req.user && req.user.id;
  const { amount } = req.body || {};

  if (typeof amount !== 'number' || isNaN(amount) || amount <= 0) {
    return res.status(400).json({ message: 'Invalid deposit amount' });
  }

  if (!uid || !accounts[uid]) {
    return res.status(404).json({ message: 'Account not found' });
  }

  accounts[uid].balance += amount;
  return res.json({
    message: `Deposited $${amount}`,
    newBalance: accounts[uid].balance
  });
});

// --- Protected: withdraw ---
app.post('/withdraw', verifyToken, (req, res) => {
  const uid = req.user && req.user.id;
  const { amount } = req.body || {};

  if (typeof amount !== 'number' || isNaN(amount) || amount <= 0) {
    return res.status(400).json({ message: 'Invalid withdrawal amount' });
  }

  if (!uid || !accounts[uid]) {
    return res.status(404).json({ message: 'Account not found' });
  }

  if (accounts[uid].balance < amount) {
    return res.status(403).json({ message: 'Insufficient balance' });
  }

  accounts[uid].balance -= amount;
  return res.json({
    message: `Withdrew $${amount}`,
    newBalance: accounts[uid].balance
  });
});

// --- Public root ---
app.get('/', (req, res) => {
  res.send('Banking API (demo) - use /login to receive a token.');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
