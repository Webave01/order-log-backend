require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Auth middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Initialize database tables
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS extras (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    `);
    
    // Check if admin user exists, if not create default users
    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const adminHash = await bcrypt.hash('admin123', 10);
      const attendantHash = await bcrypt.hash('webster123', 10);
      await client.query(
        'INSERT INTO users (username, password, role) VALUES ($1, $2, $3), ($4, $5, $6)',
        ['admin', adminHash, 'admin', 'webstaff', attendantHash, 'attendant']
      );
      console.log('Default users created');
    }
    
    // Check if settings exist
    const settingsCheck = await client.query('SELECT COUNT(*) FROM settings');
    if (parseInt(settingsCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO settings (key, value) VALUES 
        ('sameDayMult', '1.0'),
        ('defaultRate', '2.00')
      `);
      console.log('Default settings created');
    }
    
    // Check if extras exist, if not create default extras (including new rug/carpet items)
    const extrasCheck = await client.query('SELECT COUNT(*) FROM extras');
    if (parseInt(extrasCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO extras (name, price) VALUES 
        ('Blanket - SM', 8.00),
        ('Blanket - MED', 12.00),
        ('Blanket - LG', 15.00),
        ('Comforter - SM', 15.00),
        ('Comforter - MED', 20.00),
        ('Comforter - LG', 25.00),
        ('Rug - SM', 15.00),
        ('Rug - MED', 25.00),
        ('Rug - LG', 40.00),
        ('Carpet - MED', 35.00),
        ('Carpet - LG', 50.00)
      `);
      console.log('Default extras created');
    }
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// ============ AUTH ROUTES ============

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { id: user.id, username: user.username, role: user.role } 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authenticate, async (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

// ============ ORDERS ROUTES ============

app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM orders ORDER BY created_at DESC LIMIT 500'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get orders error:', err);
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
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE orders SET 
        order_num = $1, cleaner_id = $2, weight = $3, service_type = $4, 
        pickup_date = $5, bag_color = $6, extras = $7, notes = $8, staff_name = $9, updated_at = CURRENT_TIMESTAMP
       WHERE id = $10 RETURNING *`,
      [order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras || [], notes || '', staff_name || '', id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update order error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query('DELETE FROM orders WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete order error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check for duplicate orders
app.get('/api/orders/check-duplicate', authenticate, async (req, res) => {
  const { order_num, cleaner_id, exclude_id } = req.query;
  
  try {
    let query = 'SELECT id, order_num, pickup_date FROM orders WHERE order_num = $1 AND cleaner_id = $2';
    let params = [order_num, cleaner_id];
    
    if (exclude_id) {
      query += ' AND id != $3';
      params.push(exclude_id);
    }
    
    const result = await pool.query(query, params);
    
    if (result.rows.length > 0) {
      res.json({ isDuplicate: true, existingOrder: result.rows[0] });
    } else {
      res.json({ isDuplicate: false });
    }
  } catch (err) {
    console.error('Check duplicate error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check order sequence - NEW
app.get('/api/orders/check-sequence', authenticate, async (req, res) => {
  const { order_num, cleaner_id } = req.query;
  
  try {
    // Get the last order for this cleaner from today
    const today = new Date().toISOString().split('T')[0];
    const result = await pool.query(
      `SELECT order_num FROM orders 
       WHERE cleaner_id = $1 AND pickup_date = $2 
       ORDER BY created_at DESC LIMIT 1`,
      [cleaner_id, today]
    );
    
    if (result.rows.length === 0) {
      res.json({ isOutOfSequence: false });
    } else {
      const lastOrderNum = parseInt(result.rows[0].order_num) || 0;
      const currentOrderNum = parseInt(order_num) || 0;
      const diff = Math.abs(currentOrderNum - lastOrderNum);
      
      if (diff >= 50) {
        res.json({ 
          isOutOfSequence: true, 
          lastOrderNum: result.rows[0].order_num,
          difference: diff
        });
      } else {
        res.json({ isOutOfSequence: false });
      }
    }
  } catch (err) {
    console.error('Check sequence error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Import orders
app.post('/api/orders/import', authenticate, adminOnly, async (req, res) => {
  const { orders } = req.body;
  
  if (!orders || !Array.isArray(orders)) {
    return res.status(400).json({ error: 'orders array is required' });
  }
  
  const client = await pool.connect();
  let imported = 0;
  let skipped = 0;
  const errors = [];
  
  try {
    await client.query('BEGIN');
    
    for (const order of orders) {
      try {
        if (!order.order_num || !order.cleaner_id || !order.weight) {
          skipped++;
          errors.push(`Missing required fields for order ${order.order_num || 'unknown'}`);
          continue;
        }
        
        await client.query(
          `INSERT INTO orders (order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            order.order_num,
            order.cleaner_id,
            order.weight,
            order.service_type || '24-hour',
            order.pickup_date || new Date().toISOString().split('T')[0],
            order.bag_color || 'White',
            order.extras || [],
            order.notes || '',
            order.staff_name || ''
          ]
        );
        imported++;
      } catch (orderErr) {
        skipped++;
        errors.push(`Error importing order ${order.order_num}: ${orderErr.message}`);
      }
    }
    
    await client.query('COMMIT');
    res.json({ imported, skipped, errors: errors.slice(0, 10) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Import error:', err);
    res.status(500).json({ error: 'Import failed' });
  } finally {
    client.release();
  }
});

// Export orders
app.get('/api/orders/export', authenticate, adminOnly, async (req, res) => {
  try {
    const ordersResult = await pool.query(`
      SELECT o.*, c.name as cleaner_name, c.rate as cleaner_rate, c.route
      FROM orders o
      JOIN cleaners c ON o.cleaner_id = c.id
      ORDER BY o.pickup_date DESC, o.created_at DESC
    `);
    
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });
    
    const orders = ordersResult.rows.map(o => {
      const rate = parseFloat(o.cleaner_rate);
      const weight = parseFloat(o.weight);
      const mult = o.service_type === 'same-day' ? settings.sameDayMult : 1;
      const baseTotal = weight * rate * mult;
      
      const extrasNames = (o.extras || []).map(id => extrasMap[id]?.name || '').filter(n => n).join(', ');
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + parseFloat(extrasMap[id]?.price || 0), 0);
      const total = baseTotal + extrasTotal;
      
      return {
        id: o.id,
        order_num: o.order_num,
        cleaner_name: o.cleaner_name,
        route: o.route,
        weight: o.weight,
        rate_per_lb: rate,
        service_type: o.service_type,
        pickup_date: o.pickup_date,
        bag_color: o.bag_color,
        extras: extrasNames,
        extras_total: extrasTotal,
        base_total: baseTotal,
        total: total,
        notes: o.notes || '',
        staff_name: o.staff_name || '',
        created_at: o.created_at
      };
    });
    
    res.json({ orders, extrasMap, settings });
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Clear all orders - NEW (Admin only)
app.delete('/api/orders/clear-all', authenticate, adminOnly, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM orders');
    res.json({ success: true, deleted: result.rowCount });
  } catch (err) {
    console.error('Clear orders error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ CLEANERS ROUTES ============

app.get('/api/cleaners', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaners ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error('Get cleaners error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaners', authenticate, adminOnly, async (req, res) => {
  const { name, address, rate, route } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO cleaners (name, address, rate, route) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, address, rate, route || 'east']
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create cleaner error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/cleaners/:id', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { name, address, rate, route } = req.body;
  try {
    const result = await pool.query(
      'UPDATE cleaners SET name=$1, address=$2, rate=$3, route=$4 WHERE id=$5 RETURNING *',
      [name, address, rate, route, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cleaner not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update cleaner error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaners/:id', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const orderCheck = await pool.query('SELECT COUNT(*) FROM orders WHERE cleaner_id = $1', [id]);
    if (parseInt(orderCheck.rows[0].count) > 0) {
      return res.status(400).json({ error: 'Cannot delete cleaner with existing orders' });
    }
    
    const result = await pool.query('DELETE FROM cleaners WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cleaner not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete cleaner error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ EXTRAS ROUTES ============

app.get('/api/extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM extras ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error('Get extras error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/extras', authenticate, adminOnly, async (req, res) => {
  const { name, price } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO extras (name, price) VALUES ($1, $2) RETURNING *',
      [name, price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create extra error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/extras/:id', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  try {
    const result = await pool.query(
      'UPDATE extras SET name=$1, price=$2 WHERE id=$3 RETURNING *',
      [name, price, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Extra not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update extra error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/extras/:id', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM extras WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Extra not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete extra error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ SETTINGS ROUTES ============

app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM settings');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.key] = parseFloat(row.value);
    });
    res.json(settings);
  } catch (err) {
    console.error('Get settings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/settings', authenticate, adminOnly, async (req, res) => {
  const { sameDayMult, defaultRate } = req.body;
  try {
    await pool.query('UPDATE settings SET value = $1 WHERE key = $2', [sameDayMult.toString(), 'sameDayMult']);
    await pool.query('UPDATE settings SET value = $1 WHERE key = $2', [defaultRate.toString(), 'defaultRate']);
    res.json({ sameDayMult, defaultRate });
  } catch (err) {
    console.error('Update settings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ REPORTS ROUTES ============

app.get('/api/reports/invoice', authenticate, adminOnly, async (req, res) => {
  const { cleaner_id, start_date, end_date } = req.query;
  
  if (!cleaner_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'cleaner_id, start_date, and end_date are required' });
  }
  
  try {
    const ordersResult = await pool.query(
      `SELECT o.*, c.name as cleaner_name, c.rate as cleaner_rate 
       FROM orders o 
       JOIN cleaners c ON o.cleaner_id = c.id 
       WHERE o.cleaner_id = $1 AND o.pickup_date >= $2 AND o.pickup_date <= $3
       ORDER BY o.pickup_date`,
      [cleaner_id, start_date, end_date]
    );
    
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    
    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });
    
    const orders = ordersResult.rows.map(o => {
      const rate = parseFloat(o.cleaner_rate);
      const weight = parseFloat(o.weight);
      const mult = o.service_type === 'same-day' ? settings.sameDayMult : 1;
      const baseTotal = weight * rate * mult;
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + parseFloat(extrasMap[id]?.price || 0), 0);
      
      // Build formatted extras string (e.g., "1 LG Blanket + 1 MED Rug")
      const extrasCounts = {};
      (o.extras || []).forEach(id => {
        const name = extrasMap[id]?.name || '';
        if (name) {
          extrasCounts[name] = (extrasCounts[name] || 0) + 1;
        }
      });
      const extrasFormatted = Object.entries(extrasCounts)
        .map(([name, count]) => `${count} ${name}`)
        .join(' + ');
      
      return { 
        ...o, 
        total: baseTotal + extrasTotal,
        extras_formatted: extrasFormatted,
        extras_total: extrasTotal
      };
    });
    
    const grandTotal = orders.reduce((sum, o) => sum + o.total, 0);
    
    res.json({ orders, grandTotal, extrasMap });
  } catch (err) {
    console.error('Invoice report error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/daily-stats', authenticate, adminOnly, async (req, res) => {
  const { start_date, end_date } = req.query;
  
  if (!start_date || !end_date) {
    return res.status(400).json({ error: 'start_date and end_date are required' });
  }
  
  try {
    const routeStats = await pool.query(`
      SELECT 
        o.pickup_date,
        c.route,
        COUNT(o.id) as order_count,
        SUM(o.weight) as total_weight
      FROM orders o
      JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2
      GROUP BY o.pickup_date, c.route
      ORDER BY o.pickup_date, c.route
    `, [start_date, end_date]);
    
    const serviceStats = await pool.query(`
      SELECT 
        pickup_date,
        service_type,
        COUNT(id) as order_count,
        SUM(weight) as total_weight
      FROM orders
      WHERE pickup_date >= $1 AND pickup_date <= $2
      GROUP BY pickup_date, service_type
      ORDER BY pickup_date, service_type
    `, [start_date, end_date]);
    
    const totalsResult = await pool.query(`
      SELECT 
        COUNT(o.id) as total_orders,
        SUM(o.weight) as total_weight,
        SUM(CASE WHEN c.route = 'east' THEN 1 ELSE 0 END) as east_orders,
        SUM(CASE WHEN c.route = 'east' THEN o.weight ELSE 0 END) as east_weight,
        SUM(CASE WHEN c.route = 'west' THEN 1 ELSE 0 END) as west_orders,
        SUM(CASE WHEN c.route = 'west' THEN o.weight ELSE 0 END) as west_weight,
        SUM(CASE WHEN o.service_type = 'same-day' THEN 1 ELSE 0 END) as same_day_orders,
        SUM(CASE WHEN o.service_type = 'same-day' THEN o.weight ELSE 0 END) as same_day_weight,
        SUM(CASE WHEN o.service_type = '24-hour' THEN 1 ELSE 0 END) as twenty_four_hour_orders,
        SUM(CASE WHEN o.service_type = '24-hour' THEN o.weight ELSE 0 END) as twenty_four_hour_weight
      FROM orders o
      JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2
    `, [start_date, end_date]);
    
    res.json({
      routeStats: routeStats.rows,
      serviceStats: serviceStats.rows,
      totals: totalsResult.rows[0]
    });
  } catch (err) {
    console.error('Daily stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initialize and start server
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
