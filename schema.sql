-- SeaLink BD Database Schema
-- MariaDB / MySQL

USE sealink_bd;

-- ========================================
-- 1. LOCATION
-- ========================================
CREATE TABLE IF NOT EXISTS locations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  division VARCHAR(50) NOT NULL,
  district VARCHAR(50) NOT NULL,
  upazila VARCHAR(50),
  address VARCHAR(255),
  latitude DECIMAL(10, 7),
  longitude DECIMAL(10, 7),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================================
-- 2. USERS
-- ========================================
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  phone VARCHAR(20) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('SUPPLIER', 'BUYER', 'ADMIN') NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  phone_verified BOOLEAN DEFAULT FALSE,
  location_id INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE SET NULL,
  INDEX idx_username (username),
  INDEX idx_email (email),
  INDEX idx_phone (phone)
);

-- ========================================
-- 3. FISHERMAN_PROFILE
-- ========================================
CREATE TABLE IF NOT EXISTS fisherman_profiles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  boat_name VARCHAR(100),
  license_no VARCHAR(50),
  experience_years INT DEFAULT 0,
  rating_avg DECIMAL(3, 2) DEFAULT 0.00,
  total_orders INT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========================================
-- 4. BUYER_PROFILE
-- ========================================
CREATE TABLE IF NOT EXISTS buyer_profiles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  business_type ENUM('RESTAURANT', 'RETAILER', 'EXPORTER', 'CONSUMER') DEFAULT 'CONSUMER',
  business_name VARCHAR(100),
  address VARCHAR(255),
  rating_avg DECIMAL(3, 2) DEFAULT 0.00,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========================================
-- 5. FISH_CATEGORY
-- ========================================
CREATE TABLE IF NOT EXISTS fish_categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name_bn VARCHAR(50) NOT NULL,
  name_en VARCHAR(50) NOT NULL,
  image_url VARCHAR(500),
  is_active BOOLEAN DEFAULT TRUE
);

-- ========================================
-- 6. FISH_LISTING
-- ========================================
CREATE TABLE IF NOT EXISTS fish_listings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  supplier_id INT NOT NULL,
  fish_category_id INT NOT NULL,
  quantity_kg DECIMAL(10, 2) NOT NULL,
  price_per_kg DECIMAL(10, 2) NOT NULL,
  catch_date DATE,
  location_id INT,
  image_urls TEXT,
  video_url VARCHAR(500),
  description TEXT,
  status ENUM('AVAILABLE', 'SOLD', 'EXPIRED') DEFAULT 'AVAILABLE',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (supplier_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (fish_category_id) REFERENCES fish_categories(id),
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE SET NULL,
  INDEX idx_status (status),
  INDEX idx_supplier (supplier_id)
);

-- ========================================
-- 7. STOCK
-- ========================================
CREATE TABLE IF NOT EXISTS stocks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  supplier_id INT NOT NULL,
  fish_category_id INT NOT NULL,
  available_kg DECIMAL(10, 2) DEFAULT 0,
  reserved_kg DECIMAL(10, 2) DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (supplier_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (fish_category_id) REFERENCES fish_categories(id),
  UNIQUE KEY unique_supplier_fish (supplier_id, fish_category_id)
);

-- ========================================
-- 8. DEMAND_REQUEST
-- ========================================
CREATE TABLE IF NOT EXISTS demand_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  buyer_id INT NOT NULL,
  fish_category_id INT NOT NULL,
  quantity_kg DECIMAL(10, 2) NOT NULL,
  needed_by_date DATE,
  location_id INT,
  max_price_per_kg DECIMAL(10, 2),
  notes TEXT,
  status ENUM('OPEN', 'MATCHED', 'CLOSED') DEFAULT 'OPEN',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (fish_category_id) REFERENCES fish_categories(id),
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE SET NULL
);

-- ========================================
-- 9. ORDERS
-- ========================================
CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  buyer_id INT NOT NULL,
  supplier_id INT NOT NULL,
  listing_id INT,
  demand_request_id INT,
  total_price DECIMAL(10, 2) NOT NULL,
  delivery_date DATE,
  delivery_location_id INT,
  status ENUM('PENDING', 'CONFIRMED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED') DEFAULT 'PENDING',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (supplier_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (listing_id) REFERENCES fish_listings(id) ON DELETE SET NULL,
  FOREIGN KEY (demand_request_id) REFERENCES demand_requests(id) ON DELETE SET NULL,
  FOREIGN KEY (delivery_location_id) REFERENCES locations(id) ON DELETE SET NULL
);

-- ========================================
-- 10. ORDER_ITEM
-- ========================================
CREATE TABLE IF NOT EXISTS order_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL,
  fish_category_id INT NOT NULL,
  quantity_kg DECIMAL(10, 2) NOT NULL,
  price_per_kg DECIMAL(10, 2) NOT NULL,
  subtotal DECIMAL(10, 2) NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (fish_category_id) REFERENCES fish_categories(id)
);

-- ========================================
-- 11. COMMENT
-- ========================================
CREATE TABLE IF NOT EXISTS comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  listing_id INT NOT NULL,
  parent_comment_id INT,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (listing_id) REFERENCES fish_listings(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE,
  INDEX idx_listing (listing_id)
);

-- ========================================
-- 12. REACTION
-- ========================================
CREATE TABLE IF NOT EXISTS reactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  listing_id INT NOT NULL,
  type ENUM('LIKE', 'DISLIKE') NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (listing_id) REFERENCES fish_listings(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_listing (user_id, listing_id),
  INDEX idx_listing (listing_id)
);

-- ========================================
-- 13. RATING
-- ========================================
CREATE TABLE IF NOT EXISTS ratings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rater_id INT NOT NULL,
  ratee_id INT NOT NULL,
  order_id INT,
  score INT NOT NULL CHECK (score BETWEEN 1 AND 5),
  review TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (rater_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (ratee_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE SET NULL
);

-- ========================================
-- 14. DELIVERY
-- ========================================
CREATE TABLE IF NOT EXISTS deliveries (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL UNIQUE,
  transporter_id INT,
  current_lat DECIMAL(10, 7),
  current_lng DECIMAL(10, 7),
  status ENUM('ASSIGNED', 'PICKED', 'IN_TRANSIT', 'DELIVERED') DEFAULT 'ASSIGNED',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (transporter_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ========================================
-- 15. PAYMENT
-- ========================================
CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL UNIQUE,
  method ENUM('CASH', 'BKASH', 'NAGAD', 'BANK') DEFAULT 'CASH',
  amount DECIMAL(10, 2) NOT NULL,
  status ENUM('PENDING', 'COMPLETED', 'FAILED', 'REFUNDED') DEFAULT 'PENDING',
  transaction_id VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

-- ========================================
-- 16. NOTIFICATION
-- ========================================
CREATE TABLE IF NOT EXISTS notifications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  type ENUM('ORDER', 'COMMENT', 'LIKE', 'RATING', 'SYSTEM') NOT NULL,
  content TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_read (user_id, is_read)
);

-- ========================================
-- 17. REPORT
-- ========================================
CREATE TABLE IF NOT EXISTS reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  type ENUM('ORDER_INVOICE', 'MONTHLY_SALES', 'DEMAND_SUMMARY') NOT NULL,
  generated_by INT NOT NULL,
  file_url VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS otp_store (
  identifier VARCHAR(100) PRIMARY KEY,
  otp VARCHAR(10) NOT NULL,
  expires_at DATETIME NOT NULL
);

-- ========================================
-- SEED DATA — Fish Categories
-- ========================================
INSERT INTO fish_categories (name_bn, name_en) VALUES
('রুই', 'Rohu'),
('কাতলা', 'Catla'),
('ইলিশ', 'Hilsa'),
('চিংড়ি', 'Shrimp'),
('পাঙ্গাশ', 'Pangas'),
('তেলাপিয়া', 'Tilapia'),
('মৃগেল', 'Mrigal'),
('বোয়াল', 'Boal'),
('শিং', 'Shing'),
('মাগুর', 'Magur');
