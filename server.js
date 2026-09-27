const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { pool, testConnection } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sealink_secret_2026';

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendEmailOTP(email, otp) {
  console.log(`\n📧 [EMAIL OTP] To: ${email} → OTP: ${otp}\n`);
}

function sendPhoneOTP(phone, otp) {
  console.log(`\n📱 [SMS OTP] To: ${phone} → OTP: ${otp}\n`);
}

app.get('/', (req, res) => {
  res.json({ message: 'SeaLink BD API running (MariaDB)' });
});

// ---------- Register ----------
app.post('/auth/register', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { name, username, email, phone, password, role } = req.body;

    if (!name || !username || !email || !phone || !password || !role) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    const [existing] = await conn.query(
      'SELECT username, email, phone FROM users WHERE username = ? OR email = ? OR phone = ? LIMIT 1',
      [username, email, phone]
    );

    if (existing.length > 0) {
      const r = existing[0];
      let msg = 'User already exists';
      if (r.username === username) msg = 'Username already taken';
      else if (r.email === email) msg = 'Email already registered';
      else if (r.phone === phone) msg = 'Phone already registered';
      return res.status(400).json({ success: false, message: msg });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await conn.query(
      `INSERT INTO users (name, username, email, phone, password_hash, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, username, email, phone, hashedPassword, role]
    );

    const emailOtp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await conn.query(
      `INSERT INTO otp_store (identifier, otp, expires_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE otp = ?, expires_at = ?`,
      [`email_${email}`, emailOtp, expiresAt, emailOtp, expiresAt]
    );
    sendEmailOTP(email, emailOtp);

    res.status(201).json({
      success: true,
      message: 'Registered. Please verify your email.',
      nextStep: 'email_verify',
      email,
      phone,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Resend Email OTP ----------
app.post('/auth/resend-email-otp', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { email } = req.body;
    const [users] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await conn.query(
      `INSERT INTO otp_store (identifier, otp, expires_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE otp = ?, expires_at = ?`,
      [`email_${email}`, otp, expiresAt, otp, expiresAt]
    );
    sendEmailOTP(email, otp);
    res.json({ success: true, message: 'OTP resent to email' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Verify Email OTP ----------
app.post('/auth/verify-email', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { email, otp } = req.body;

    const [records] = await conn.query(
      'SELECT otp, expires_at FROM otp_store WHERE identifier = ?',
      [`email_${email}`]
    );

    if (records.length === 0) {
      return res.status(400).json({ success: false, message: 'No OTP requested' });
    }
    const record = records[0];
    if (new Date() > new Date(record.expires_at)) {
      await conn.query('DELETE FROM otp_store WHERE identifier = ?', [`email_${email}`]);
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }
    if (record.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    await conn.query('UPDATE users SET email_verified = TRUE WHERE email = ?', [email]);
    await conn.query('DELETE FROM otp_store WHERE identifier = ?', [`email_${email}`]);

    const [users] = await conn.query('SELECT phone FROM users WHERE email = ?', [email]);
    const phone = users[0].phone;
    const phoneOtp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await conn.query(
      `INSERT INTO otp_store (identifier, otp, expires_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE otp = ?, expires_at = ?`,
      [`phone_${phone}`, phoneOtp, expiresAt, phoneOtp, expiresAt]
    );
    sendPhoneOTP(phone, phoneOtp);

    res.json({
      success: true,
      message: 'Email verified. Now verify phone.',
      nextStep: 'phone_verify',
      phone,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Resend Phone OTP ----------
app.post('/auth/resend-phone-otp', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { phone } = req.body;
    const [users] = await conn.query('SELECT id FROM users WHERE phone = ?', [phone]);
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await conn.query(
      `INSERT INTO otp_store (identifier, otp, expires_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE otp = ?, expires_at = ?`,
      [`phone_${phone}`, otp, expiresAt, otp, expiresAt]
    );
    sendPhoneOTP(phone, otp);
    res.json({ success: true, message: 'OTP resent to phone' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Verify Phone OTP ----------
app.post('/auth/verify-phone', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { phone, otp } = req.body;

    const [records] = await conn.query(
      'SELECT otp, expires_at FROM otp_store WHERE identifier = ?',
      [`phone_${phone}`]
    );

    if (records.length === 0) {
      return res.status(400).json({ success: false, message: 'No OTP requested' });
    }
    const record = records[0];
    if (new Date() > new Date(record.expires_at)) {
      await conn.query('DELETE FROM otp_store WHERE identifier = ?', [`phone_${phone}`]);
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }
    if (record.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    await conn.query('UPDATE users SET phone_verified = TRUE WHERE phone = ?', [phone]);
    await conn.query('DELETE FROM otp_store WHERE identifier = ?', [`phone_${phone}`]);

    const [users] = await conn.query(
      `SELECT id, name, username, email, phone, role, email_verified, phone_verified, created_at
       FROM users WHERE phone = ?`,
      [phone]
    );
    const user = users[0];

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Registration complete!',
      token,
      user,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Login ----------
app.post('/auth/login', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    const [users] = await conn.query(
      'SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1',
      [username, username]
    );
    if (users.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const user = users[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (!user.email_verified || !user.phone_verified) {
      return res.status(403).json({
        success: false,
        message: 'Account not verified. Please complete verification.',
        nextStep: !user.email_verified ? 'email_verify' : 'phone_verify',
        email: user.email,
        phone: user.phone,
      });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    delete user.password_hash;
    res.json({ success: true, message: 'Login successful', token, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Check Username ----------
app.get('/auth/check-username/:username', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [req.params.username]
    );
    res.json({ success: true, available: rows.length === 0 });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ---------- Me (protected) ----------
app.get('/auth/me', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token' });
    }
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    const [users] = await conn.query(
      `SELECT id, name, username, email, phone, role, email_verified, phone_verified, created_at
       FROM users WHERE id = ?`,
      [decoded.id]
    );
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, user: users[0] });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  } finally {
    conn.release();
  }
});

const PORT = process.env.PORT || 3000;

(async () => {
  await testConnection();
  app.listen(PORT, () => {
    console.log(`SeaLink BD API running on http://localhost:${PORT}`);
  });
})();
