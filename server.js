const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sealink_secret_2026';

// In-memory store (পরে PostgreSQL দিয়ে replace করব)
const users = [];
const otpStore = {}; // { email/phone: { otp, expiresAt, purpose } }

// ---------- Helper: Generate 6-digit OTP ----------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------- Helper: Send OTP (dev: console print) ----------
function sendEmailOTP(email, otp) {
  // TODO: production-এ Nodemailer/SendGrid use করব
  console.log(`\n📧 [EMAIL OTP] To: ${email} → OTP: ${otp}\n`);
}

function sendPhoneOTP(phone, otp) {
  // TODO: production-এ Twilio/local SMS gateway use করব
  console.log(`\n📱 [SMS OTP] To: ${phone} → OTP: ${otp}\n`);
}

// ---------- Health ----------
app.get('/', (req, res) => {
  res.json({ message: 'SeaLink BD API running' });
});

// ---------- Register (Step 1: form submit) ----------
app.post('/auth/register', async (req, res) => {
  try {
    const { name, username, email, phone, password, role } = req.body;

    if (!name || !username || !email || !phone || !password || !role) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    if (users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, message: 'Username already taken' });
    }
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    if (users.find(u => u.phone === phone)) {
      return res.status(400).json({ success: false, message: 'Phone already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: users.length + 1,
      name,
      username,
      email,
      phone,
      password: hashedPassword,
      role,
      emailVerified: false,
      phoneVerified: false,
      createdAt: new Date().toISOString(),
    };
    users.push(user);

    // Email OTP পাঠাই
    const emailOtp = generateOTP();
    otpStore[`email_${email}`] = {
      otp: emailOtp,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
    };
    sendEmailOTP(email, emailOtp);

    res.status(201).json({
      success: true,
      message: 'Registered. Please verify your email.',
      nextStep: 'email_verify',
      email,
      phone,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---------- Resend Email OTP ----------
app.post('/auth/resend-email-otp', (req, res) => {
  const { email } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  const otp = generateOTP();
  otpStore[`email_${email}`] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };
  sendEmailOTP(email, otp);
  res.json({ success: true, message: 'OTP resent to email' });
});

// ---------- Verify Email OTP ----------
app.post('/auth/verify-email', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[`email_${email}`];

  if (!record) return res.status(400).json({ success: false, message: 'No OTP requested' });
  if (Date.now() > record.expiresAt) {
    delete otpStore[`email_${email}`];
    return res.status(400).json({ success: false, message: 'OTP expired' });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  // Mark email verified
  const user = users.find(u => u.email === email);
  user.emailVerified = true;
  delete otpStore[`email_${email}`];

  // Now send phone OTP
  const phoneOtp = generateOTP();
  otpStore[`phone_${user.phone}`] = {
    otp: phoneOtp,
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
  sendPhoneOTP(user.phone, phoneOtp);

  res.json({
    success: true,
    message: 'Email verified. Now verify phone.',
    nextStep: 'phone_verify',
    phone: user.phone,
  });
});

// ---------- Resend Phone OTP ----------
app.post('/auth/resend-phone-otp', (req, res) => {
  const { phone } = req.body;
  const user = users.find(u => u.phone === phone);
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  const otp = generateOTP();
  otpStore[`phone_${phone}`] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };
  sendPhoneOTP(phone, otp);
  res.json({ success: true, message: 'OTP resent to phone' });
});

// ---------- Verify Phone OTP (final step) ----------
app.post('/auth/verify-phone', (req, res) => {
  const { phone, otp } = req.body;
  const record = otpStore[`phone_${phone}`];

  if (!record) return res.status(400).json({ success: false, message: 'No OTP requested' });
  if (Date.now() > record.expiresAt) {
    delete otpStore[`phone_${phone}`];
    return res.status(400).json({ success: false, message: 'OTP expired' });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  const user = users.find(u => u.phone === phone);
  user.phoneVerified = true;
  delete otpStore[`phone_${phone}`];

  // Issue JWT now
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const { password: _, ...userSafe } = user;
  res.json({
    success: true,
    message: 'Registration complete!',
    token,
    user: userSafe,
  });
});

// ---------- Login ----------
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    const user = users.find(u => u.username === username || u.email === username);
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    if (!user.emailVerified || !user.phoneVerified) {
      return res.status(403).json({
        success: false,
        message: 'Account not verified. Please complete verification.',
        nextStep: !user.emailVerified ? 'email_verify' : 'phone_verify',
        email: user.email,
        phone: user.phone,
      });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { password: _, ...userSafe } = user;
    res.json({ success: true, message: 'Login successful', token, user: userSafe });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---------- Check Username ----------
app.get('/auth/check-username/:username', (req, res) => {
  const exists = users.some(u => u.username === req.params.username);
  res.json({ success: true, available: !exists });
});

// ---------- Me (protected) ----------
app.get('/auth/me', (req, res) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    const user = users.find(u => u.id === decoded.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { password: _, ...userSafe } = user;
    res.json({ success: true, user: userSafe });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SeaLink BD API running on http://localhost:${PORT}`);
});
