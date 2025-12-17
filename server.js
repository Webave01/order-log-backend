require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'attendant',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS cleaners (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        address VARCHAR(255),
        rate DECIMAL(10,2) NOT NULL,
        route VARCHAR(20) NOT NULL DEFAULT 'east',
        min_weight DECIMAL(10,2) DEFAULT 10,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS extras (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        category VARCHAR(50) DEFAULT 'Other',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS cleaner_extras (
        id SERIAL PRIMARY KEY,
        cleaner_id INTEGER REFERENCES cleaners(id) ON DELETE CASCADE,
        extra_id INTEGER REFERENCES extras(id) ON DELETE CASCADE,
        custom_price DECIMAL(10,2) NOT NULL,
        UNIQUE(cleaner_id, extra_id)
      );
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        order_num VARCHAR(50) NOT NULL,
        cleaner_id INTEGER REFERENCES cleaners(id),
        weight DECIMAL(10,2) NOT NULL,
        service_type VARCHAR(20) NOT NULL DEFAULT '24-hour',
        pickup_date DATE NOT NULL,
        bag_color VARCHAR(50) DEFAULT 'White',
        extras INTEGER[] DEFAULT '{}',
        notes TEXT,
        staff_name VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(50) UNIQUE NOT NULL,
        value VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS invoice_tracking (
        id SERIAL PRIMARY KEY,
        cleaner_id INTEGER REFERENCES cleaners(id) ON DELETE CASCADE,
        week_start DATE NOT NULL,
        week_end DATE NOT NULL,
        invoice_amount DECIMAL(10,2) NOT NULL,
        amount_paid DECIMAL(10,2) DEFAULT 0,
        paid_date DATE,
        status VARCHAR(20) DEFAULT 'unpaid',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(cleaner_id, week_start)
      );
    `);
    
    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const adminHash = await bcrypt.hash('admin123', 10);
      const attendantHash = await bcrypt.hash('webster123', 10);
      await client.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3), ($4, $5, $6)',
        ['admin', adminHash, 'admin', 'webstaff', attendantHash, 'attendant']);
    }
    
    const settingsCheck = await client.query('SELECT COUNT(*) FROM settings');
    if (parseInt(settingsCheck.rows[0].count) === 0) {
      await client.query(`INSERT INTO settings (key, value) VALUES ('sameDayMult', '1.0'), ('defaultRate', '0.85'), ('autoClearDays', '90')`);
    }
    
    const extrasCheck = await client.query('SELECT COUNT(*) FROM extras');
    if (parseInt(extrasCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO extras (name, price, category) VALUES 
        ('Blanket - SM', 8.00, 'Blanket'), ('Blanket - MED', 12.00, 'Blanket'), ('Blanket - LG', 15.00, 'Blanket'),
        ('Comforter - SM', 15.00, 'Comforter'), ('Comforter - MED', 20.00, 'Comforter'), ('Comforter - LG', 25.00, 'Comforter'),
        ('Rug - SM', 15.00, 'Rug'), ('Rug - MED', 25.00, 'Rug'), ('Rug - LG', 40.00, 'Rug'),
        ('Carpet - MED', 35.00, 'Carpet'), ('Carpet - LG', 50.00, 'Carpet'),
        ('Mat - SM', 10.00, 'Mat'), ('Mat - MED', 15.00, 'Mat'), ('Mat - LG', 20.00, 'Mat')
      `);
    }

    try { await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS staff_name VARCHAR(50)`); } catch(e) {}
    try { await client.query(`ALTER TABLE cleaners ADD COLUMN IF NOT EXISTS min_weight DECIMAL(10,2) DEFAULT 10`); } catch(e) {}
    try { await client.query(`ALTER TABLE extras ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'Other'`); } catch(e) {}
    
    console.log('Database initialized');
  } catch (err) {
    console.error('DB init error:', err);
  } finally {
    client.release();
  }
}

// Auto-clear old orders (runs daily)
async function autoClearOldOrders() {
  try {
    const settingsResult = await pool.query("SELECT value FROM settings WHERE key = 'autoClearDays'");
    const days = settingsResult.rows.length > 0 ? parseInt(settingsResult.rows[0].value) : 90;
    if (days > 0) {
      const result = await pool.query(`DELETE FROM orders WHERE pickup_date < CURRENT_DATE - INTERVAL '1 day' * $1`, [days]);
      console.log(`Auto-cleared ${result.rowCount} orders older than ${days} days`);
    }
  } catch (err) {
    console.error('Auto-clear error:', err.message);
  }
}

setInterval(autoClearOldOrders, 24 * 60 * 60 * 1000);

// ============ AUTH ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authenticate, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

// ============ ORDERS - SPECIFIC ROUTES FIRST (before /:id) ============

app.delete('/api/orders/clear-all', authenticate, adminOnly, async (req, res) => {
  console.log('=== CLEAR ALL ORDERS ===');
  try {
    const countResult = await pool.query('SELECT COUNT(*) FROM orders');
    const count = parseInt(countResult.rows[0].count);
    console.log('Orders to delete:', count);
    await pool.query('DELETE FROM orders');
    console.log('Deleted successfully');
    res.json({ success: true, deleted: count });
  } catch (err) {
    console.error('CLEAR ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders/check-duplicate', authenticate, async (req, res) => {
  const { order_num, cleaner_id, exclude_id } = req.query;
  try {
    let query = 'SELECT id, order_num, pickup_date, cleaner_id FROM orders WHERE order_num = $1';
    let params = [order_num];
    if (cleaner_id) { query += ' AND cleaner_id = $2'; params.push(cleaner_id); }
    if (exclude_id) { query += ` AND id != $${params.length + 1}`; params.push(exclude_id); }
    const result = await pool.query(query, params);
    res.json(result.rows.length > 0 ? { isDuplicate: true, existingOrder: result.rows[0] } : { isDuplicate: false });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/check-sequence', authenticate, async (req, res) => {
  const { order_num, cleaner_id } = req.query;
  try {
    // Get the last few orders for this cleaner to find the highest order number
    const result = await pool.query(
      `SELECT order_num FROM orders WHERE cleaner_id = $1 ORDER BY created_at DESC LIMIT 10`,
      [cleaner_id]
    );
    if (result.rows.length === 0) return res.json({ isOutOfSequence: false });
    
    // Find the highest numeric order number from recent orders
    let lastNum = 0;
    let lastOrderNum = '';
    for (const row of result.rows) {
      const num = parseInt(row.order_num) || 0;
      if (num > lastNum) {
        lastNum = num;
        lastOrderNum = row.order_num;
      }
    }
    
    const currNum = parseInt(order_num) || 0;
    const diff = Math.abs(currNum - lastNum);
    
    // Flag if difference is 50 or more (either direction)
    const isOutOfSequence = diff >= 50;
    res.json(isOutOfSequence ? { isOutOfSequence: true, lastOrderNum, difference: diff } : { isOutOfSequence: false });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/find-duplicates', authenticate, adminOnly, async (req, res) => {
  const { cleaner_id, start_date, end_date } = req.query;
  try {
    let query = `SELECT order_num, COUNT(*) as count FROM orders WHERE pickup_date >= $1 AND pickup_date <= $2`;
    let params = [start_date, end_date];
    if (cleaner_id) { query += ' AND cleaner_id = $3'; params.push(cleaner_id); }
    query += ' GROUP BY order_num HAVING COUNT(*) > 1';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders/import', authenticate, adminOnly, async (req, res) => {
  const { orders } = req.body;
  if (!orders || !Array.isArray(orders)) return res.status(400).json({ error: 'orders array required' });
  let imported = 0, skipped = 0;
  for (const order of orders) {
    try {
      if (!order.order_num || !order.cleaner_id || !order.weight) { skipped++; continue; }
      await pool.query(
        `INSERT INTO orders (order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [order.order_num, order.cleaner_id, order.weight, order.service_type || '24-hour', order.pickup_date || new Date().toISOString().split('T')[0], order.bag_color || 'White', order.extras || [], order.notes || '', order.staff_name || '']
      );
      imported++;
    } catch (e) { skipped++; }
  }
  res.json({ imported, skipped });
});

app.get('/api/orders/export', authenticate, adminOnly, async (req, res) => {
  try {
    const ordersResult = await pool.query(`
      SELECT o.*, c.name as cleaner_name, c.rate as cleaner_rate, c.route, c.min_weight
      FROM orders o JOIN cleaners c ON o.cleaner_id = c.id ORDER BY o.pickup_date DESC
    `);
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {}; extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {}; settingsResult.rows.forEach(r => { settings[r.key] = parseFloat(r.value); });

    const orders = ordersResult.rows.map(o => {
      const rate = parseFloat(o.cleaner_rate);
      const weight = parseFloat(o.weight);
      const minWeight = parseFloat(o.min_weight) || 10;
      const mult = o.service_type === 'same-day' ? (settings.sameDayMult || 1) : 1;
      const billableWeight = weight === 0 ? 0 : Math.max(weight, minWeight);
      const baseTotal = billableWeight * rate * mult;
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + parseFloat(extrasMap[id]?.price || 0), 0);
      const extrasNames = (o.extras || []).map(id => extrasMap[id]?.name || '').filter(n => n).join(', ');
      return {
        order_num: o.order_num, cleaner_name: o.cleaner_name, route: o.route, weight: o.weight,
        rate_per_lb: rate, service_type: o.service_type, pickup_date: o.pickup_date, bag_color: o.bag_color,
        extras: extrasNames, extras_total: extrasTotal, total: baseTotal + extrasTotal, notes: o.notes || '', staff_name: o.staff_name || ''
      };
    });
    res.json({ orders, settings });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ ORDERS - GENERIC ROUTES ============
app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const { search, limit } = req.query;
    let query = 'SELECT * FROM orders';
    let params = [];
    
    if (search) {
      query += ' WHERE order_num ILIKE $1';
      params.push('%' + search + '%');
    }
    
    query += ' ORDER BY created_at DESC';
    
    if (limit) {
      query += ' LIMIT $' + (params.length + 1);
      params.push(parseInt(limit));
    }
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders', authenticate, async (req, res) => {
  const { order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO orders (order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [order_num, cleaner_id, weight, service_type || '24-hour', pickup_date, bag_color || 'White', extras || [], notes || '', staff_name || '']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name } = req.body;
  try {
    const result = await pool.query(
      `UPDATE orders SET order_num=$1, cleaner_id=$2, weight=$3, service_type=$4, pickup_date=$5, bag_color=$6, extras=$7, notes=$8, staff_name=$9, updated_at=CURRENT_TIMESTAMP WHERE id=$10 RETURNING *`,
      [order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras || [], notes || '', staff_name || '', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/orders/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM orders WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ CLEANERS ============
app.get('/api/cleaners', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaners ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaners', authenticate, adminOnly, async (req, res) => {
  const { name, address, rate, route, min_weight } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO cleaners (name, address, rate, route, min_weight) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, address, rate, route || 'east', min_weight || 10]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/cleaners/:id', authenticate, adminOnly, async (req, res) => {
  const { name, address, rate, route, min_weight } = req.body;
  try {
    const result = await pool.query(
      'UPDATE cleaners SET name=$1, address=$2, rate=$3, route=$4, min_weight=$5 WHERE id=$6 RETURNING *',
      [name, address, rate, route, min_weight || 10, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cleaner not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaners/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const orderCheck = await pool.query('SELECT COUNT(*) FROM orders WHERE cleaner_id = $1', [req.params.id]);
    if (parseInt(orderCheck.rows[0].count) > 0) return res.status(400).json({ error: 'Cannot delete cleaner with orders' });
    const result = await pool.query('DELETE FROM cleaners WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cleaner not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/cleaners/:id/extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaner_extras WHERE cleaner_id = $1', [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaners/:id/extras', authenticate, adminOnly, async (req, res) => {
  const { extra_id, custom_price } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO cleaner_extras (cleaner_id, extra_id, custom_price) VALUES ($1, $2, $3)
       ON CONFLICT (cleaner_id, extra_id) DO UPDATE SET custom_price = $3 RETURNING *`,
      [req.params.id, extra_id, custom_price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaners/:id/extras/:extraId', authenticate, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM cleaner_extras WHERE cleaner_id = $1 AND extra_id = $2', [req.params.id, req.params.extraId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ EXTRAS ============
app.get('/api/extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM extras ORDER BY category, name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/extras', authenticate, adminOnly, async (req, res) => {
  const { name, price, category } = req.body;
  try {
    const result = await pool.query('INSERT INTO extras (name, price, category) VALUES ($1, $2, $3) RETURNING *', [name, price, category || 'Other']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/extras/:id', authenticate, adminOnly, async (req, res) => {
  const { name, price, category } = req.body;
  try {
    const result = await pool.query('UPDATE extras SET name=$1, price=$2, category=$3 WHERE id=$4 RETURNING *', [name, price, category || 'Other', req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Extra not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/extras/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM extras WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Extra not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ SETTINGS ============
app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM settings');
    const settings = {}; result.rows.forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/settings', authenticate, adminOnly, async (req, res) => {
  const { sameDayMult, defaultRate, autoClearDays } = req.body;
  try {
    if (sameDayMult !== undefined) await pool.query("INSERT INTO settings (key, value) VALUES ('sameDayMult', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [sameDayMult.toString()]);
    if (defaultRate !== undefined) await pool.query("INSERT INTO settings (key, value) VALUES ('defaultRate', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [defaultRate.toString()]);
    if (autoClearDays !== undefined) await pool.query("INSERT INTO settings (key, value) VALUES ('autoClearDays', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [autoClearDays.toString()]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ REPORTS ============
app.get('/api/reports/invoice', authenticate, adminOnly, async (req, res) => {
  const { cleaner_id, start_date, end_date } = req.query;
  if (!cleaner_id || !start_date || !end_date) return res.status(400).json({ error: 'Missing params' });
  
  try {
    const cleanerResult = await pool.query('SELECT * FROM cleaners WHERE id = $1', [cleaner_id]);
    if (cleanerResult.rows.length === 0) return res.status(404).json({ error: 'Cleaner not found' });
    const cleaner = cleanerResult.rows[0];
    
    const ordersResult = await pool.query(
      `SELECT o.*, c.rate as cleaner_rate, c.min_weight FROM orders o JOIN cleaners c ON o.cleaner_id = c.id
       WHERE o.cleaner_id = $1 AND o.pickup_date >= $2 AND o.pickup_date <= $3 ORDER BY o.pickup_date, o.order_num`,
      [cleaner_id, start_date, end_date]
    );
    
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {}; extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    
    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras WHERE cleaner_id = $1', [cleaner_id]);
    const customPrices = {}; cleanerExtrasResult.rows.forEach(ce => { customPrices[ce.extra_id] = parseFloat(ce.custom_price); });
    
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {}; settingsResult.rows.forEach(r => { settings[r.key] = parseFloat(r.value); });

    // Check for sequence gaps
    const sequenceWarnings = [];
    const sortedByNum = [...ordersResult.rows].sort((a, b) => (parseInt(a.order_num) || 0) - (parseInt(b.order_num) || 0));
    for (let i = 1; i < sortedByNum.length; i++) {
      const prevNum = parseInt(sortedByNum[i-1].order_num) || 0;
      const currNum = parseInt(sortedByNum[i].order_num) || 0;
      const diff = currNum - prevNum;
      if (diff >= 50 || diff <= -50) {
        sequenceWarnings.push({ from: sortedByNum[i-1].order_num, to: sortedByNum[i].order_num, gap: diff });
      }
    }

    const orders = ordersResult.rows.map(o => {
      const rate = parseFloat(o.cleaner_rate);
      const weight = parseFloat(o.weight);
      const minWeight = parseFloat(o.min_weight) || 10;
      const mult = o.service_type === 'same-day' ? (settings.sameDayMult || 1) : 1;
      const billableWeight = weight === 0 ? 0 : Math.max(weight, minWeight);
      const baseTotal = billableWeight * rate * mult;
      
      const extrasCounts = {};
      let extrasTotal = 0;
      (o.extras || []).forEach(id => {
        const ex = extrasMap[id];
        if (ex) {
          const price = customPrices[id] !== undefined ? customPrices[id] : parseFloat(ex.price);
          extrasTotal += price;
          extrasCounts[ex.name] = (extrasCounts[ex.name] || 0) + 1;
        }
      });
      const extrasFormatted = Object.entries(extrasCounts).map(([n, c]) => c > 1 ? `${c}x ${n}` : n).join(', ');
      
      return { ...o, total: baseTotal + extrasTotal, extras_formatted: extrasFormatted, extras_total: extrasTotal };
    });

    res.json({ orders, grandTotal: orders.reduce((sum, o) => sum + o.total, 0), cleaner, extrasMap, sequenceWarnings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/invoices-all', authenticate, adminOnly, async (req, res) => {
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'Missing params' });
  
  try {
    const cleanersResult = await pool.query('SELECT * FROM cleaners ORDER BY name');
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {}; extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras');
    const cleanerCustomPrices = {};
    cleanerExtrasResult.rows.forEach(ce => {
      if (!cleanerCustomPrices[ce.cleaner_id]) cleanerCustomPrices[ce.cleaner_id] = {};
      cleanerCustomPrices[ce.cleaner_id][ce.extra_id] = parseFloat(ce.custom_price);
    });
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {}; settingsResult.rows.forEach(r => { settings[r.key] = parseFloat(r.value); });
    
    const invoices = [];
    for (const cleaner of cleanersResult.rows) {
      const ordersResult = await pool.query(
        `SELECT o.*, c.rate as cleaner_rate, c.min_weight FROM orders o JOIN cleaners c ON o.cleaner_id = c.id
         WHERE o.cleaner_id = $1 AND o.pickup_date >= $2 AND o.pickup_date <= $3 ORDER BY o.pickup_date, o.order_num`,
        [cleaner.id, start_date, end_date]
      );
      if (ordersResult.rows.length === 0) continue;
      
      const customPrices = cleanerCustomPrices[cleaner.id] || {};
      const orders = ordersResult.rows.map(o => {
        const rate = parseFloat(o.cleaner_rate);
        const weight = parseFloat(o.weight);
        const minWeight = parseFloat(o.min_weight) || 10;
        const billableWeight = weight === 0 ? 0 : Math.max(weight, minWeight);
        const baseTotal = billableWeight * rate * (o.service_type === 'same-day' ? (settings.sameDayMult || 1) : 1);
        
        let extrasTotal = 0;
        const extrasCounts = {};
        (o.extras || []).forEach(id => {
          const ex = extrasMap[id];
          if (ex) {
            extrasTotal += customPrices[id] !== undefined ? customPrices[id] : parseFloat(ex.price);
            extrasCounts[ex.name] = (extrasCounts[ex.name] || 0) + 1;
          }
        });
        return { ...o, total: baseTotal + extrasTotal, extras_formatted: Object.entries(extrasCounts).map(([n, c]) => c > 1 ? `${c}x ${n}` : n).join(', ') };
      });
      invoices.push({ cleaner, orders, grandTotal: orders.reduce((sum, o) => sum + o.total, 0) });
    }
    res.json({ invoices });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/daily-stats', authenticate, adminOnly, async (req, res) => {
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'Missing params' });
  
  try {
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {}; extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {}; settingsResult.rows.forEach(r => { settings[r.key] = parseFloat(r.value); });
    
    const ordersResult = await pool.query(`
      SELECT o.*, c.route, c.rate, c.min_weight, c.name as cleaner_name FROM orders o JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2 ORDER BY o.pickup_date
    `, [start_date, end_date]);
    
    let totalOrders = 0, totalWeight = 0, totalAmount = 0;
    let eastOrders = 0, eastWeight = 0, eastAmount = 0;
    let westOrders = 0, westWeight = 0, westAmount = 0;
    let sameDayOrders = 0, sameDayWeight = 0, hour24Orders = 0, hour24Weight = 0;
    const dailyBreakdown = {};
    const cleanerBreakdown = {};
    
    ordersResult.rows.forEach(o => {
      const rate = parseFloat(o.rate);
      const weight = parseFloat(o.weight);
      const minWeight = parseFloat(o.min_weight) || 10;
      const billableWeight = weight === 0 ? 0 : Math.max(weight, minWeight);
      const baseTotal = billableWeight * rate * (o.service_type === 'same-day' ? (settings.sameDayMult || 1) : 1);
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + parseFloat(extrasMap[id]?.price || 0), 0);
      const total = baseTotal + extrasTotal;
      
      totalOrders++; totalWeight += weight; totalAmount += total;
      if (o.route === 'east') { eastOrders++; eastWeight += weight; eastAmount += total; }
      else { westOrders++; westWeight += weight; westAmount += total; }
      if (o.service_type === 'same-day') { sameDayOrders++; sameDayWeight += weight; }
      else { hour24Orders++; hour24Weight += weight; }
      
      const dateKey = typeof o.pickup_date === 'string' ? o.pickup_date.split('T')[0] : o.pickup_date.toISOString().split('T')[0];
      if (!dailyBreakdown[dateKey]) dailyBreakdown[dateKey] = { date: dateKey, orders: 0, weight: 0, amount: 0, eastOrders: 0, eastAmount: 0, westOrders: 0, westAmount: 0 };
      dailyBreakdown[dateKey].orders++; dailyBreakdown[dateKey].weight += weight; dailyBreakdown[dateKey].amount += total;
      if (o.route === 'east') { dailyBreakdown[dateKey].eastOrders++; dailyBreakdown[dateKey].eastAmount += total; }
      else { dailyBreakdown[dateKey].westOrders++; dailyBreakdown[dateKey].westAmount += total; }
      
      // Cleaner breakdown
      const cleanerKey = o.cleaner_id;
      if (!cleanerBreakdown[cleanerKey]) cleanerBreakdown[cleanerKey] = { name: o.cleaner_name, route: o.route, orders: 0, weight: 0, amount: 0 };
      cleanerBreakdown[cleanerKey].orders++;
      cleanerBreakdown[cleanerKey].weight += weight;
      cleanerBreakdown[cleanerKey].amount += total;
    });
    
    res.json({
      totals: { total_orders: totalOrders, total_weight: totalWeight, total_amount: totalAmount, east_orders: eastOrders, east_weight: eastWeight, east_amount: eastAmount, west_orders: westOrders, west_weight: westWeight, west_amount: westAmount, same_day_orders: sameDayOrders, same_day_weight: sameDayWeight, twenty_four_hour_orders: hour24Orders, twenty_four_hour_weight: hour24Weight },
      dailyBreakdown: Object.values(dailyBreakdown).sort((a, b) => a.date.localeCompare(b.date)),
      cleanerBreakdown: Object.values(cleanerBreakdown).sort((a, b) => b.amount - a.amount)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ INVOICE TRACKING ============
app.get('/api/invoice-tracking', authenticate, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT it.*, c.name as cleaner_name, c.route 
      FROM invoice_tracking it 
      JOIN cleaners c ON it.cleaner_id = c.id 
      ORDER BY it.week_start DESC, c.name
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoice-tracking', authenticate, adminOnly, async (req, res) => {
  const { cleaner_id, week_start, week_end, invoice_amount } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO invoice_tracking (cleaner_id, week_start, week_end, invoice_amount) 
       VALUES ($1, $2, $3, $4) 
       ON CONFLICT (cleaner_id, week_start) DO UPDATE SET invoice_amount = $4
       RETURNING *`,
      [cleaner_id, week_start, week_end, invoice_amount]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoice-tracking/generate-week', authenticate, adminOnly, async (req, res) => {
  const { week_start, week_end } = req.body;
  try {
    // Get invoice totals for all cleaners for this week
    const invoicesResult = await pool.query(`
      SELECT o.cleaner_id, c.name, c.rate, c.min_weight,
             SUM(CASE WHEN o.weight = 0 THEN 0 ELSE GREATEST(o.weight, c.min_weight) END * c.rate) as base_total,
             o.extras
      FROM orders o
      JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2
      GROUP BY o.cleaner_id, c.name, c.rate, c.min_weight, o.extras
    `, [week_start, week_end]);
    
    // Calculate totals per cleaner including extras
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {}; extrasResult.rows.forEach(e => { extrasMap[e.id] = parseFloat(e.price); });
    
    const cleanerTotals = {};
    const ordersResult = await pool.query(`
      SELECT o.cleaner_id, o.weight, o.extras, o.service_type, c.rate, c.min_weight
      FROM orders o JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2
    `, [week_start, week_end]);
    
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {}; settingsResult.rows.forEach(r => { settings[r.key] = parseFloat(r.value); });
    
    ordersResult.rows.forEach(o => {
      if (!cleanerTotals[o.cleaner_id]) cleanerTotals[o.cleaner_id] = 0;
      const weight = parseFloat(o.weight);
      const minWeight = parseFloat(o.min_weight) || 10;
      const billableWeight = weight === 0 ? 0 : Math.max(weight, minWeight);
      const mult = o.service_type === 'same-day' ? (settings.sameDayMult || 1) : 1;
      const baseTotal = billableWeight * parseFloat(o.rate) * mult;
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + (extrasMap[id] || 0), 0);
      cleanerTotals[o.cleaner_id] += baseTotal + extrasTotal;
    });
    
    // Insert or update invoice tracking records
    let created = 0;
    for (const [cleaner_id, amount] of Object.entries(cleanerTotals)) {
      if (amount > 0) {
        await pool.query(
          `INSERT INTO invoice_tracking (cleaner_id, week_start, week_end, invoice_amount) 
           VALUES ($1, $2, $3, $4) 
           ON CONFLICT (cleaner_id, week_start) DO UPDATE SET invoice_amount = $4`,
          [cleaner_id, week_start, week_end, amount]
        );
        created++;
      }
    }
    
    res.json({ success: true, created });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/invoice-tracking/:id', authenticate, adminOnly, async (req, res) => {
  const { amount_paid, paid_date, status, notes } = req.body;
  try {
    const result = await pool.query(
      `UPDATE invoice_tracking SET amount_paid = $1, paid_date = $2, status = $3, notes = $4 WHERE id = $5 RETURNING *`,
      [amount_paid || 0, paid_date || null, status || 'unpaid', notes || '', req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/invoice-tracking/:id', authenticate, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM invoice_tracking WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/invoice-tracking/summary', authenticate, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id as cleaner_id, c.name as cleaner_name, c.route,
             COALESCE(SUM(it.invoice_amount), 0) as total_invoiced,
             COALESCE(SUM(it.amount_paid), 0) as total_paid,
             COALESCE(SUM(it.invoice_amount - it.amount_paid), 0) as total_due
      FROM cleaners c
      LEFT JOIN invoice_tracking it ON c.id = it.cleaner_id
      GROUP BY c.id, c.name, c.route
      ORDER BY total_due DESC
    `);
    const overall = result.rows.reduce((acc, r) => ({
      total_invoiced: acc.total_invoiced + parseFloat(r.total_invoiced),
      total_paid: acc.total_paid + parseFloat(r.total_paid),
      total_due: acc.total_due + parseFloat(r.total_due)
    }), { total_invoiced: 0, total_paid: 0, total_due: 0 });
    res.json({ cleaners: result.rows, overall });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

initDB().then(() => {
  autoClearOldOrders();
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
