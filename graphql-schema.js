const { buildSchema } = require('graphql');
const { pool } = require('./db');

// ১. Schema Definition (কী কী ডাটা চাওয়া যাবে)
const schema = buildSchema(`
  type FishListing {
    id: Int!
    fishNameBn: String!
    fishNameEn: String!
    quantityKg: Float!
    pricePerKg: Float!
    supplierName: String!
    status: String!
    location: String
  }

  type User {
    id: Int!
    name: String!
    username: String!
    email: String!
    role: String!
  }

  type Query {
    getAllListings(limit: Int): [FishListing]
    getListingById(id: Int!): FishListing
    getUsers: [User]
    getPlatformStats: String
  }
`);

// ২. Resolvers (ডাটাবেস থেকে ডাটা কীভাবে আসবে)
const root = {
  // সব লিস্টিং নিয়ে আসা
  getAllListings: async (args) => {
    const conn = await pool.getConnection();
    try {
      const limit = args.limit || 10;
      const [rows] = await conn.query(
        `SELECT 
          fl.id, fl.quantity_kg, fl.price_per_kg, fl.status,
          fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
          u.name AS supplier_name, l.district
         FROM fish_listings fl
         JOIN fish_categories fc ON fl.fish_category_id = fc.id
         JOIN users u ON fl.supplier_id = u.id
         LEFT JOIN locations l ON fl.location_id = l.id
         ORDER BY fl.created_at DESC LIMIT ?`,
        [limit]
      );
      
      return rows.map(r => ({
        id: r.id,
        fishNameBn: r.fish_name_bn,
        fishNameEn: r.fish_name_en,
        quantityKg: parseFloat(r.quantity_kg),
        pricePerKg: parseFloat(r.price_per_kg),
        supplierName: r.supplier_name,
        status: r.status,
        location: r.district || 'Unknown'
      }));
    } finally {
      conn.release();
    }
  },

  // নির্দিষ্ট আইডি দিয়ে একটি লিস্টিং খোঁজা
  getListingById: async (args) => {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(
        `SELECT 
          fl.id, fl.quantity_kg, fl.price_per_kg, fl.status,
          fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
          u.name AS supplier_name, l.district
         FROM fish_listings fl
         JOIN fish_categories fc ON fl.fish_category_id = fc.id
         JOIN users u ON fl.supplier_id = u.id
         LEFT JOIN locations l ON fl.location_id = l.id
         WHERE fl.id = ?`,
        [args.id]
      );
      
      if (rows.length === 0) return null;
      const r = rows[0];
      return {
        id: r.id,
        fishNameBn: r.fish_name_bn,
        fishNameEn: r.fish_name_en,
        quantityKg: parseFloat(r.quantity_kg),
        pricePerKg: parseFloat(r.price_per_kg),
        supplierName: r.supplier_name,
        status: r.status,
        location: r.district || 'Unknown'
      };
    } finally {
      conn.release();
    }
  },

  // সব ইউজার নিয়ে আসা
  getUsers: async () => {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(
        'SELECT id, name, username, email, role FROM users WHERE role != "ADMIN" LIMIT 10'
      );
      return rows;
    } finally {
      conn.release();
    }
  },

  // প্ল্যাটফর্মের সাধারণ পরিসংখ্যান
  getPlatformStats: async () => {
    const conn = await pool.getConnection();
    try {
      const [[users]] = await conn.query('SELECT COUNT(*) AS c FROM users');
      const [[listings]] = await conn.query('SELECT COUNT(*) AS c FROM fish_listings');
      const [[orders]] = await conn.query('SELECT COUNT(*) AS c FROM orders');
      return `Total Users: ${users.c}, Listings: ${listings.c}, Orders: ${orders.c}`;
    } finally {
      conn.release();
    }
  }
};

module.exports = { schema, root };