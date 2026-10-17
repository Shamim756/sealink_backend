const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const cloudinary = require('./cloudinary');
const multer = require('multer');
require('dotenv').config();

const { pool, testConnection } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

const upload = multer({ storage: multer.memoryStorage() });

const JWT_SECRET = process.env.JWT_SECRET || 'sealink_secret_2026';

// ==========================================
// HELPERS
// ==========================================
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendEmailOTP(email, otp) {
  console.log(`\n📧 [EMAIL OTP] To: ${email} → OTP: ${otp}\n`);
}

function sendPhoneOTP(phone, otp) {
  console.log(`\n📱 [SMS OTP] To: ${phone} → OTP: ${otp}\n`);
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    } catch {}
  }
  next();
}

// ==========================================
// SOCKET.IO
// ==========================================
io.on('connection', (socket) => {
  console.log('🟢 Socket connected:', socket.id);

  socket.on('join_listing', (listingId) => {
    socket.join(`listing_${listingId}`);
  });

  socket.on('leave_listing', (listingId) => {
    socket.leave(`listing_${listingId}`);
  });

  socket.on('join_user', (userId) => {
    socket.join(`user_${userId}`);
  });

  socket.on('disconnect', () => {
    console.log('🔴 Socket disconnected:', socket.id);
  });
});

// ==========================================
// HEALTH
// ==========================================
app.get('/', (req, res) => {
  res.json({ message: 'SeaLink BD API running (MariaDB + Socket.io)' });
});

// ==========================================
// AUTH — REGISTER
// ==========================================
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
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// AUTH — RESEND EMAIL OTP
// ==========================================
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

// ==========================================
// AUTH — VERIFY EMAIL
// ==========================================
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

// ==========================================
// AUTH — RESEND PHONE OTP
// ==========================================
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

// ==========================================
// AUTH — VERIFY PHONE
// ==========================================
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

// ==========================================
// AUTH — LOGIN
// ==========================================
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

// ==========================================
// AUTH — CHECK USERNAME
// ==========================================
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

// ==========================================
// AUTH — ME
// ==========================================
app.get('/auth/me', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [users] = await conn.query(
      `SELECT id, name, username, email, phone, role, email_verified, phone_verified, created_at
       FROM users WHERE id = ?`,
      [req.user.id]
    );
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, user: users[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// FISH CATEGORIES
// ==========================================
app.get('/fish-categories', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT id, name_bn, name_en, image_url FROM fish_categories WHERE is_active = TRUE'
    );
    res.json({ success: true, categories: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LOCATIONS
// ==========================================
app.get('/locations', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT id, division, district, upazila FROM locations ORDER BY division, district'
    );
    res.json({ success: true, locations: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LISTINGS — CREATE
// ==========================================
app.post('/listings', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== 'SUPPLIER') {
      return res.status(403).json({ success: false, message: 'Only suppliers can create listings' });
    }

    const {
      fish_category_id,
      quantity_kg,
      price_per_kg,
      catch_date,
      location_id,
      image_urls,
      video_url,
      description,
    } = req.body;

    if (!fish_category_id || !quantity_kg || !price_per_kg) {
      return res.status(400).json({ success: false, message: 'Fish, quantity, and price required' });
    }

    const [result] = await conn.query(
      `INSERT INTO fish_listings
       (supplier_id, fish_category_id, quantity_kg, price_per_kg, catch_date, location_id, image_urls, video_url, description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        fish_category_id,
        quantity_kg,
        price_per_kg,
        catch_date || null,
        location_id || null,
        image_urls ? JSON.stringify(image_urls) : null,
        video_url || null,
        description || null,
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Listing created',
      listing_id: result.insertId,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LISTINGS — GET ALL (with FILTERS)
// ==========================================
app.get('/listings', optionalAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    // Filter params
    const fishCategoryId = req.query.fish_category_id;
    const locationId = req.query.location_id;
    const minPrice = req.query.min_price ? parseFloat(req.query.min_price) : null;
    const maxPrice = req.query.max_price ? parseFloat(req.query.max_price) : null;
    const search = req.query.search;

    // Build WHERE clause
    const conditions = ["fl.status = 'AVAILABLE'"];
    const params = [];

    if (fishCategoryId) {
      conditions.push('fl.fish_category_id = ?');
      params.push(fishCategoryId);
    }

    if (locationId) {
      conditions.push('fl.location_id = ?');
      params.push(locationId);
    }

    if (minPrice !== null) {
      conditions.push('fl.price_per_kg >= ?');
      params.push(minPrice);
    }

    if (maxPrice !== null) {
      conditions.push('fl.price_per_kg <= ?');
      params.push(maxPrice);
    }

    if (search && search.trim() !== '') {
      conditions.push('(fc.name_bn LIKE ? OR fc.name_en LIKE ? OR fl.description LIKE ?)');
      const searchPattern = `%${search.trim()}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    const whereClause = conditions.join(' AND ');

    // Fetch listings
    const [listings] = await conn.query(
      `SELECT 
        fl.id, fl.quantity_kg, fl.price_per_kg, fl.catch_date, fl.image_urls, fl.video_url,
        fl.description, fl.status, fl.created_at,
        fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en, fc.image_url AS fish_image,
        u.id AS supplier_id, u.name AS supplier_name, u.username AS supplier_username,
        l.division, l.district, l.upazila,
        (SELECT COUNT(*) FROM reactions r WHERE r.listing_id = fl.id AND r.type = 'LIKE') AS like_count,
        (SELECT COUNT(*) FROM reactions r WHERE r.listing_id = fl.id AND r.type = 'DISLIKE') AS dislike_count
       FROM fish_listings fl
       JOIN fish_categories fc ON fl.fish_category_id = fc.id
       JOIN users u ON fl.supplier_id = u.id
       LEFT JOIN locations l ON fl.location_id = l.id
       WHERE ${whereClause}
       ORDER BY fl.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    // Count total
    const [[{ total }]] = await conn.query(
      `SELECT COUNT(*) AS total
       FROM fish_listings fl
       JOIN fish_categories fc ON fl.fish_category_id = fc.id
       WHERE ${whereClause}`,
      params
    );

    // User reactions
    let userReactions = {};
    if (req.user) {
      const listingIds = listings.map(l => l.id);
      if (listingIds.length > 0) {
        const [rows] = await conn.query(
          'SELECT listing_id, type FROM reactions WHERE user_id = ? AND listing_id IN (?)',
          [req.user.id, listingIds]
        );
        rows.forEach(r => { userReactions[r.listing_id] = r.type; });
      }
    }

    listings.forEach((l) => {
      if (l.image_urls) {
        try { l.image_urls = JSON.parse(l.image_urls); } catch { l.image_urls = []; }
      } else {
        l.image_urls = [];
      }
      l.user_reaction = userReactions[l.id] || null;
    });

    res.json({
      success: true,
      listings,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LISTINGS — GET ONE
// ==========================================
app.get('/listings/:id', optionalAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [listings] = await conn.query(
      `SELECT 
        fl.*,
        fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
        u.name AS supplier_name, u.username AS supplier_username,
        l.division, l.district, l.upazila,
        (SELECT COUNT(*) FROM reactions r WHERE r.listing_id = fl.id AND r.type = 'LIKE') AS like_count,
        (SELECT COUNT(*) FROM reactions r WHERE r.listing_id = fl.id AND r.type = 'DISLIKE') AS dislike_count
       FROM fish_listings fl
       JOIN fish_categories fc ON fl.fish_category_id = fc.id
       JOIN users u ON fl.supplier_id = u.id
       LEFT JOIN locations l ON fl.location_id = l.id
       WHERE fl.id = ?`,
      [req.params.id]
    );

    if (listings.length === 0) {
      return res.status(404).json({ success: false, message: 'Listing not found' });
    }

    const listing = listings[0];
    if (listing.image_urls) {
      try { listing.image_urls = JSON.parse(listing.image_urls); } catch { listing.image_urls = []; }
    } else {
      listing.image_urls = [];
    }

    listing.user_reaction = null;
    if (req.user) {
      const [r] = await conn.query(
        'SELECT type FROM reactions WHERE user_id = ? AND listing_id = ?',
        [req.user.id, req.params.id]
      );
      if (r.length > 0) listing.user_reaction = r[0].type;
    }

    res.json({ success: true, listing });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LISTINGS — UPDATE
// ==========================================
app.put('/listings/:id', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT supplier_id FROM fish_listings WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Listing not found' });
    }
    if (rows[0].supplier_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Not your listing' });
    }

    const { quantity_kg, price_per_kg, catch_date, location_id, description, status } = req.body;

    await conn.query(
      `UPDATE fish_listings SET
        quantity_kg = COALESCE(?, quantity_kg),
        price_per_kg = COALESCE(?, price_per_kg),
        catch_date = COALESCE(?, catch_date),
        location_id = COALESCE(?, location_id),
        description = COALESCE(?, description),
        status = COALESCE(?, status)
       WHERE id = ?`,
      [quantity_kg, price_per_kg, catch_date, location_id, description, status, req.params.id]
    );

    res.json({ success: true, message: 'Listing updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// LISTINGS — DELETE
// ==========================================
app.delete('/listings/:id', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT supplier_id FROM fish_listings WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Listing not found' });
    }
    if (rows[0].supplier_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Not your listing' });
    }

    await conn.query('DELETE FROM fish_listings WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Listing deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// REACTIONS
// ==========================================
app.post('/listings/:id/react', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { type } = req.body;
    if (type !== 'LIKE' && type !== 'DISLIKE') {
      return res.status(400).json({ success: false, message: 'Invalid reaction type' });
    }

    const listingId = req.params.id;

    const [existing] = await conn.query(
      'SELECT id, type FROM reactions WHERE user_id = ? AND listing_id = ?',
      [req.user.id, listingId]
    );

    let userReaction = null;

    if (existing.length > 0) {
      const current = existing[0];
      if (current.type === type) {
        await conn.query('DELETE FROM reactions WHERE id = ?', [current.id]);
        userReaction = null;
      } else {
        await conn.query('UPDATE reactions SET type = ? WHERE id = ?', [type, current.id]);
        userReaction = type;
      }
    } else {
      await conn.query(
        'INSERT INTO reactions (user_id, listing_id, type) VALUES (?, ?, ?)',
        [req.user.id, listingId, type]
      );
      userReaction = type;
    }

    const [[counts]] = await conn.query(
      `SELECT 
        (SELECT COUNT(*) FROM reactions WHERE listing_id = ? AND type = 'LIKE') AS likes,
        (SELECT COUNT(*) FROM reactions WHERE listing_id = ? AND type = 'DISLIKE') AS dislikes`,
      [listingId, listingId]
    );

    const payload = {
      listingId: parseInt(listingId),
      likes: counts.likes,
      dislikes: counts.dislikes,
    };

    io.to(`listing_${listingId}`).emit('reaction_update', payload);

    res.json({
      success: true,
      likes: counts.likes,
      dislikes: counts.dislikes,
      userReaction,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// COMMENTS — GET
// ==========================================
app.get('/listings/:id/comments', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [comments] = await conn.query(
      `SELECT 
        c.id, c.content, c.parent_comment_id, c.created_at,
        u.id AS user_id, u.name AS user_name, u.username AS user_username
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.listing_id = ?
       ORDER BY c.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, comments });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// COMMENTS — POST
// ==========================================
app.post('/listings/:id/comments', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { content, parent_comment_id } = req.body;
    if (!content || content.trim() === '') {
      return res.status(400).json({ success: false, message: 'Comment required' });
    }

    const [listings] = await conn.query(
      'SELECT id FROM fish_listings WHERE id = ?',
      [req.params.id]
    );
    if (listings.length === 0) {
      return res.status(404).json({ success: false, message: 'Listing not found' });
    }

    const [result] = await conn.query(
      `INSERT INTO comments (user_id, listing_id, parent_comment_id, content)
       VALUES (?, ?, ?, ?)`,
      [req.user.id, req.params.id, parent_comment_id || null, content.trim()]
    );

    const [rows] = await conn.query(
      `SELECT 
        c.id, c.content, c.parent_comment_id, c.created_at,
        u.id AS user_id, u.name AS user_name, u.username AS user_username
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.id = ?`,
      [result.insertId]
    );

    const newComment = rows[0];
    io.to(`listing_${req.params.id}`).emit('comment_added', newComment);

    res.status(201).json({ success: true, comment: newComment });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// RATINGS — GET USER RATING
// ==========================================
app.get('/users/:id/rating', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [[stats]] = await conn.query(
      `SELECT 
        COUNT(*) AS total,
        COALESCE(AVG(score), 0) AS average
       FROM ratings WHERE ratee_id = ?`,
      [req.params.id]
    );

    const [reviews] = await conn.query(
      `SELECT 
        r.id, r.score, r.review, r.created_at,
        u.id AS rater_id, u.name AS rater_name
       FROM ratings r
       JOIN users u ON r.rater_id = u.id
       WHERE r.ratee_id = ?
       ORDER BY r.created_at DESC
       LIMIT 10`,
      [req.params.id]
    );

    res.json({
      success: true,
      average: parseFloat(stats.average),
      total: stats.total,
      reviews,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// RATINGS — SUBMIT
// ==========================================
app.post('/ratings', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { ratee_id, order_id, score, review } = req.body;

    if (!ratee_id || !score) {
      return res.status(400).json({ success: false, message: 'Ratee and score required' });
    }
    if (score < 1 || score > 5) {
      return res.status(400).json({ success: false, message: 'Score must be 1-5' });
    }
    if (ratee_id === req.user.id) {
      return res.status(400).json({ success: false, message: 'Cannot rate yourself' });
    }

    const [result] = await conn.query(
      `INSERT INTO ratings (rater_id, ratee_id, order_id, score, review)
       VALUES (?, ?, ?, ?, ?)`,
      [req.user.id, ratee_id, order_id || null, score, review || null]
    );

    const [[stats]] = await conn.query(
      `SELECT COALESCE(AVG(score), 0) AS average
       FROM ratings WHERE ratee_id = ?`,
      [ratee_id]
    );

    io.emit('rating_update', {
      userId: ratee_id,
      average: parseFloat(stats.average),
    });

    res.status(201).json({
      success: true,
      message: 'Rating submitted',
      rating_id: result.insertId,
      new_average: parseFloat(stats.average),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// ORDERS — CREATE
// ==========================================
app.post('/orders', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== 'BUYER') {
      return res.status(403).json({ success: false, message: 'Only buyers can place orders' });
    }

    const {
      listing_id,
      quantity_kg,
      delivery_date,
      delivery_location_id,
    } = req.body;

    if (!listing_id || !quantity_kg) {
      return res.status(400).json({ success: false, message: 'Listing and quantity required' });
    }

    const [listings] = await conn.query(
      `SELECT id, supplier_id, quantity_kg, price_per_kg, fish_category_id, status
       FROM fish_listings WHERE id = ?`,
      [listing_id]
    );

    if (listings.length === 0) {
      return res.status(404).json({ success: false, message: 'Listing not found' });
    }

    const listing = listings[0];

    if (listing.status !== 'AVAILABLE') {
      return res.status(400).json({ success: false, message: 'Listing not available' });
    }

    if (quantity_kg > parseFloat(listing.quantity_kg)) {
      return res.status(400).json({
        success: false,
        message: `Only ${listing.quantity_kg} kg available`,
      });
    }

    if (listing.supplier_id === req.user.id) {
      return res.status(400).json({ success: false, message: 'Cannot order your own listing' });
    }

    const totalPrice = quantity_kg * parseFloat(listing.price_per_kg);

    const [result] = await conn.query(
      `INSERT INTO orders
       (buyer_id, supplier_id, listing_id, total_price, delivery_date, delivery_location_id, status)
       VALUES (?, ?, ?, ?, ?, ?, 'PENDING')`,
      [
        req.user.id,
        listing.supplier_id,
        listing_id,
        totalPrice,
        delivery_date || null,
        delivery_location_id || null,
      ]
    );

    const orderId = result.insertId;

    await conn.query(
      `INSERT INTO order_items (order_id, fish_category_id, quantity_kg, price_per_kg, subtotal)
       VALUES (?, ?, ?, ?, ?)`,
      [orderId, listing.fish_category_id, quantity_kg, listing.price_per_kg, totalPrice]
    );

    const [buyers] = await conn.query('SELECT name FROM users WHERE id = ?', [req.user.id]);
    const buyerName = buyers[0]?.name || 'A buyer';

    io.to(`user_${listing.supplier_id}`).emit('new_order', {
      orderId,
      buyerName,
      totalPrice,
      quantityKg: quantity_kg,
    });

    res.status(201).json({
      success: true,
      message: 'Order placed successfully',
      order_id: orderId,
      total_price: totalPrice,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// ORDERS — MY ORDERS
// ==========================================
app.get('/orders/my', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    let query, params;

    if (req.user.role === 'BUYER') {
      query = `
        SELECT 
          o.id, o.total_price, o.delivery_date, o.status, o.created_at,
          o.listing_id, o.buyer_id, o.supplier_id,
          fl.image_urls, fl.fish_category_id,
          fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
          u.name AS supplier_name, u.username AS supplier_username,
          l.division, l.district, l.upazila
        FROM orders o
        JOIN fish_listings fl ON o.listing_id = fl.id
        JOIN fish_categories fc ON fl.fish_category_id = fc.id
        JOIN users u ON o.supplier_id = u.id
        LEFT JOIN locations l ON o.delivery_location_id = l.id
        WHERE o.buyer_id = ?
        ORDER BY o.created_at DESC
      `;
      params = [req.user.id];
    } else if (req.user.role === 'SUPPLIER') {
      query = `
        SELECT 
          o.id, o.total_price, o.delivery_date, o.status, o.created_at,
          o.listing_id, o.buyer_id, o.supplier_id,
          fl.image_urls, fl.fish_category_id,
          fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
          u.name AS buyer_name, u.username AS buyer_username, u.phone AS buyer_phone,
          l.division, l.district, l.upazila
        FROM orders o
        JOIN fish_listings fl ON o.listing_id = fl.id
        JOIN fish_categories fc ON fl.fish_category_id = fc.id
        JOIN users u ON o.buyer_id = u.id
        LEFT JOIN locations l ON o.delivery_location_id = l.id
        WHERE o.supplier_id = ?
        ORDER BY o.created_at DESC
      `;
      params = [req.user.id];
    } else {
      return res.status(403).json({ success: false, message: 'Invalid role' });
    }

    const [orders] = await conn.query(query, params);

    orders.forEach((o) => {
      if (o.image_urls) {
        try { o.image_urls = JSON.parse(o.image_urls); } catch { o.image_urls = []; }
      } else {
        o.image_urls = [];
      }
    });

    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// ORDERS — GET ONE
// ==========================================
app.get('/orders/:id', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [orders] = await conn.query(
      `SELECT 
        o.*,
        fl.image_urls, fl.fish_category_id, fl.price_per_kg,
        fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
        buyer.name AS buyer_name, buyer.username AS buyer_username, buyer.phone AS buyer_phone,
        supplier.name AS supplier_name, supplier.username AS supplier_username, supplier.phone AS supplier_phone,
        l.division, l.district, l.upazila
       FROM orders o
       JOIN fish_listings fl ON o.listing_id = fl.id
       JOIN fish_categories fc ON fl.fish_category_id = fc.id
       JOIN users buyer ON o.buyer_id = buyer.id
       JOIN users supplier ON o.supplier_id = supplier.id
       LEFT JOIN locations l ON o.delivery_location_id = l.id
       WHERE o.id = ?`,
      [req.params.id]
    );

    if (orders.length === 0) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    const order = orders[0];

    if (order.buyer_id !== req.user.id && order.supplier_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    if (order.image_urls) {
      try { order.image_urls = JSON.parse(order.image_urls); } catch { order.image_urls = []; }
    } else {
      order.image_urls = [];
    }

    const [items] = await conn.query(
      `SELECT oi.*, fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en
       FROM order_items oi
       JOIN fish_categories fc ON oi.fish_category_id = fc.id
       WHERE oi.order_id = ?`,
      [req.params.id]
    );

    order.items = items;

    res.json({ success: true, order });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// ORDERS — UPDATE STATUS
// ==========================================
app.put('/orders/:id/status', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== 'SUPPLIER') {
      return res.status(403).json({ success: false, message: 'Only suppliers can update status' });
    }

    const { status } = req.body;
    const validStatuses = ['PENDING', 'CONFIRMED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED'];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const [rows] = await conn.query(
      'SELECT supplier_id, buyer_id, status FROM orders WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    if (rows[0].supplier_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Not your order' });
    }

    const oldStatus = rows[0].status;

    await conn.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);

    io.to(`user_${rows[0].buyer_id}`).emit('order_update', {
      orderId: parseInt(req.params.id),
      status,
      oldStatus,
    });

    res.json({
      success: true,
      message: `Order status updated to ${status}`,
      status,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ==========================================
// IMAGE UPLOAD
// ==========================================
app.post('/upload/image', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No image' });
    }

    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'sealink_bd/listings', resource_type: 'image' },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(req.file.buffer);
    });

    res.json({ success: true, url: result.secure_url });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;

let serverInstance;

(async () => {
  await testConnection();
  serverInstance = server.listen(PORT, () => {
    console.log(`SeaLink BD API running on http://localhost:${PORT}`);
    console.log(`🔌 Socket.io ready`);
  });

  serverInstance.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n❌ Port ${PORT} already in use!`);
      console.error(`Run: sudo fuser -k ${PORT}/tcp\n`);
    } else {
      console.error('Server error:', err);
    }
    process.exit(1);
  });
})();

const shutdown = (signal) => {
  console.log(`\n${signal} received. Closing server...`);
  if (serverInstance) {
    serverInstance.close(() => {
      console.log('Server closed. Bye!');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5000);
  } else {
    process.exit(0);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));