require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === Schedule Routes (Driver Scheduling & Pay) ===
const scheduleRoutes = require('./schedule-routes');

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

// Permission-based access: admin always allowed, others checked against permissions array
const requirePerm = (perm) => async (req, res, next) => {
  if (req.user.role === 'admin') return next();
  try {
    const result = await pool.query('SELECT permissions FROM users WHERE id = $1', [req.user.id]);
    const perms = result.rows[0]?.permissions || [];
    if (perms.includes(perm)) return next();
    return res.status(403).json({ error: 'Access denied - missing permission: ' + perm });
  } catch(e) {
    return res.status(403).json({ error: 'Access denied' });
  }
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
        congestion_zone BOOLEAN DEFAULT false,
        congestion_rate DECIMAL(10,2) DEFAULT 5.00,
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
        price_adjustment DECIMAL(10,2) DEFAULT 0,
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

    // Add congestion columns if they don't exist (for existing databases)
    await client.query(`
      ALTER TABLE cleaners ADD COLUMN IF NOT EXISTS congestion_zone BOOLEAN DEFAULT false;
      ALTER TABLE cleaners ADD COLUMN IF NOT EXISTS congestion_rate DECIMAL(10,2) DEFAULT 5.00;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS price_adjustment DECIMAL(10,2) DEFAULT 0;
    `);

    // =============================================
    // DRIVER SCHEDULING & PAY TABLES
    // =============================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS drivers (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        email VARCHAR(100),
        hourly_rate DECIMAL(10,2) NOT NULL DEFAULT 16.50,
        overtime_rate DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'active',
        hired_date DATE DEFAULT CURRENT_DATE,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS routes (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        description TEXT,
        active_days INTEGER[] DEFAULT '{1,2,3,4,5,6}',
        estimated_hours DECIMAL(4,2) DEFAULT 5.0,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS shift_templates (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS schedule_assignments (
        id SERIAL PRIMARY KEY,
        driver_id INTEGER REFERENCES drivers(id) NOT NULL,
        route_id INTEGER REFERENCES routes(id) NOT NULL,
        shift_template_id INTEGER REFERENCES shift_templates(id) NOT NULL,
        day_of_week INTEGER NOT NULL,
        is_recurring BOOLEAN DEFAULT true,
        effective_date DATE DEFAULT CURRENT_DATE,
        end_date DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(route_id, shift_template_id, day_of_week, effective_date)
      );
      CREATE TABLE IF NOT EXISTS schedule_exceptions (
        id SERIAL PRIMARY KEY,
        original_assignment_id INTEGER REFERENCES schedule_assignments(id),
        exception_date DATE NOT NULL,
        exception_type VARCHAR(20) NOT NULL,
        replacement_driver_id INTEGER REFERENCES drivers(id),
        reason TEXT,
        approved_by INTEGER REFERENCES users(id),
        approved_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS time_entries (
        id SERIAL PRIMARY KEY,
        driver_id INTEGER REFERENCES drivers(id) NOT NULL,
        route_id INTEGER REFERENCES routes(id) NOT NULL,
        shift_template_id INTEGER REFERENCES shift_templates(id),
        work_date DATE NOT NULL,
        clock_in TIMESTAMP,
        clock_out TIMESTAMP,
        break_minutes INTEGER DEFAULT 0,
        total_hours DECIMAL(5,2),
        status VARCHAR(20) DEFAULT 'pending',
        notes TEXT,
        approved_by INTEGER REFERENCES users(id),
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS pay_periods (
        id SERIAL PRIMARY KEY,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        status VARCHAR(20) DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS pay_records (
        id SERIAL PRIMARY KEY,
        pay_period_id INTEGER REFERENCES pay_periods(id) NOT NULL,
        driver_id INTEGER REFERENCES drivers(id) NOT NULL,
        regular_hours DECIMAL(5,2) DEFAULT 0,
        overtime_hours DECIMAL(5,2) DEFAULT 0,
        regular_pay DECIMAL(10,2) DEFAULT 0,
        overtime_pay DECIMAL(10,2) DEFAULT 0,
        bonuses DECIMAL(10,2) DEFAULT 0,
        gross_pay DECIMAL(10,2) DEFAULT 0,
        notes TEXT,
        status VARCHAR(20) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(pay_period_id, driver_id)
      );
    `);

    // Scheduling indexes
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_schedule_driver ON schedule_assignments(driver_id);
      CREATE INDEX IF NOT EXISTS idx_schedule_day ON schedule_assignments(day_of_week);
      CREATE INDEX IF NOT EXISTS idx_time_entries_date ON time_entries(work_date);
      CREATE INDEX IF NOT EXISTS idx_time_entries_driver ON time_entries(driver_id);
      CREATE INDEX IF NOT EXISTS idx_pay_records_period ON pay_records(pay_period_id);
      CREATE INDEX IF NOT EXISTS idx_exceptions_date ON schedule_exceptions(exception_date);
    `);

    // Seed routes and shifts if empty
    const routeCheck = await client.query('SELECT COUNT(*) FROM routes');
    if (parseInt(routeCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO routes (name, description, active_days, has_shifts) VALUES
          ('East Cleaners', 'East Side Manhattan pickups/deliveries', '{1,2,3,4,5,6}', true),
          ('West Cleaners', 'West Side Manhattan pickups/deliveries', '{1,2,3,4,5,6}', true),
          ('Laundry Day', 'Laundry Day route', '{1,2,3,4,5,6}', false),
          ('Schools', 'School pickups/deliveries', '{1,5}', false),
          ('Sleepy', 'Sleepy route', '{1,2}', false),
          ('Panda', 'Panda route', '{1,5}', false)
      `);
    } else {
      // Migration: add has_shifts column
      try { await client.query("ALTER TABLE routes ADD COLUMN IF NOT EXISTS has_shifts BOOLEAN DEFAULT false"); } catch(e) {}
      // Migration: add requires_clock_in column
      try { await client.query("ALTER TABLE routes ADD COLUMN IF NOT EXISTS requires_clock_in BOOLEAN DEFAULT false"); } catch(e) {}
      // Migration: update existing East/West and add missing routes
      await client.query("UPDATE routes SET has_shifts = true WHERE name ILIKE '%east%' OR name ILIKE '%west%'");
      await client.query("UPDATE routes SET requires_clock_in = true WHERE name ILIKE '%panda%' OR name ILIKE '%school%' OR name ILIKE '%sleepy%'");
      const routeNames = ['East Cleaners','West Cleaners','Laundry Day','Schools','Sleepy','Panda'];
      const routeDays = {'Schools':'{1,5}','Sleepy':'{1,2}','Panda':'{1,5}'};
      for (const rn of routeNames) {
        const exists = await client.query("SELECT id FROM routes WHERE name ILIKE $1", [rn]);
        if (exists.rows.length === 0) {
          const hasShifts = rn.includes('Cleaners');
          const days = routeDays[rn] || '{1,2,3,4,5,6}';
          await client.query("INSERT INTO routes (name, has_shifts, active_days) VALUES ($1, $2, $3)", [rn, hasShifts, days]);
        } else if (routeDays[rn]) {
          await client.query("UPDATE routes SET active_days = $1 WHERE name ILIKE $2", [routeDays[rn], rn]);
        }
      }
    }
    const shiftCheck = await client.query('SELECT COUNT(*) FROM shift_templates');
    if (parseInt(shiftCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO shift_templates (name, start_time, end_time) VALUES
          ('AM', '06:00', '12:00'),
          ('PM', '12:00', '18:00'),
          ('Full Day', '07:30', '23:59')
      `);
    } else {
      // Migration: add Full Day if missing
      const fdCheck = await client.query("SELECT id FROM shift_templates WHERE name = 'Full Day'");
      if (fdCheck.rows.length === 0) {
        await client.query("INSERT INTO shift_templates (name, start_time, end_time) VALUES ('Full Day', '07:30', '23:59')");
      } else {
        await client.query("UPDATE shift_templates SET start_time='07:30', end_time='23:59' WHERE name='Full Day'");
      }
    }

    // Migration: add driver profile columns
    const driverCols = [
      ['pay_type', "VARCHAR(20) DEFAULT 'hourly'"],
      ['day_rate', 'DECIMAL(10,2)'],
      ['payment_method', "VARCHAR(20) DEFAULT 'cash'"],
      ['worker_type', "VARCHAR(10) DEFAULT '1099'"],
      ['legal_name', 'VARCHAR(200)'],
      ['dob', 'DATE'],
      ['address', 'TEXT'],
      ['dl_number', 'VARCHAR(100)'],
      ['tax_id', 'VARCHAR(100)'],
      ['tax_id_type', "VARCHAR(10) DEFAULT 'ssn'"],
      ['zelle_handle', 'VARCHAR(100)']
    ];
    for (const [col, def] of driverCols) {
      try {
        await client.query('ALTER TABLE drivers ADD COLUMN IF NOT EXISTS ' + col + ' ' + def);
      } catch(e) { /* column exists */ }
    }

    // Migration: lowercase all usernames for consistent login
    await client.query('UPDATE users SET username = LOWER(username) WHERE username != LOWER(username)');

    // Driver availability requests table
    await client.query(`
      CREATE TABLE IF NOT EXISTS driver_availability (
        id SERIAL PRIMARY KEY,
        driver_id INTEGER REFERENCES drivers(id) NOT NULL,
        work_date DATE NOT NULL,
        status VARCHAR(20) DEFAULT 'available',
        preferred_route_id INTEGER REFERENCES routes(id),
        preferred_shift VARCHAR(20),
        notes TEXT,
        confirmed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(driver_id, work_date)
      )
    `);
    // Migration: add preferred_route_id if missing
    try { await client.query("ALTER TABLE driver_availability ADD COLUMN IF NOT EXISTS preferred_route_id INTEGER REFERENCES routes(id)"); } catch(e) {}
    // Migration: add admin_confirmed column
    try { await client.query("ALTER TABLE driver_availability ADD COLUMN IF NOT EXISTS admin_confirmed BOOLEAN DEFAULT false"); } catch(e) {}
    // Migration: add route_selections JSONB for multi-route support
    try { await client.query("ALTER TABLE driver_availability ADD COLUMN IF NOT EXISTS route_selections JSONB DEFAULT '[]'::jsonb"); } catch(e) {}
    // Migration: backfill route_selections from preferred_route_id
    try { await client.query(`
      UPDATE driver_availability SET route_selections = jsonb_build_array(
        jsonb_build_object('route_id', preferred_route_id, 'shift', preferred_shift)
      ) WHERE preferred_route_id IS NOT NULL AND (route_selections IS NULL OR route_selections = '[]'::jsonb)
    `); } catch(e) {}
    // Migration: add plain_password to users for admin visibility
    try { await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS plain_password VARCHAR(255)"); } catch(e) {}
    // Migration: add permissions JSONB to users for granular access control
    try { await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '[]'::jsonb"); } catch(e) {}

    // =============================================
    // END DRIVER SCHEDULING TABLES
    // =============================================

    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const adminHash = await bcrypt.hash('admin123', 10);
      const attendantHash = await bcrypt.hash('webster123', 10);
      await client.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3), ($4, $5, $6)',
        ['admin', adminHash, 'admin', 'webster', attendantHash, 'attendant']);
    }

    const settingsCheck = await client.query('SELECT COUNT(*) FROM settings');
    if (parseInt(settingsCheck.rows[0].count) === 0) {
      await client.query('INSERT INTO settings (key, value) VALUES ($1, $2), ($3, $4)',
        ['sameDayMult', '1.0', 'defaultRate', '0.65']);
    }

    console.log('Database initialized (including driver scheduling tables)');
  } catch (err) {
    console.error('DB init error:', err);
  } finally {
    client.release();
  }
}

// Auth routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    // Find linked driver if any
    let driver_id = null;
    if (user.role === 'driver') {
      const dResult = await pool.query('SELECT id FROM drivers WHERE user_id = $1', [user.id]);
      if (dResult.rows.length > 0) driver_id = dResult.rows[0].id;
    }
    // Build permissions: admin=all, driver=schedule, others=stored permissions
    const ALL_PERMS = ['orders','cleaners','extras','invoices','payments','reports','errors','schedule','settings'];
    let perms;
    if (user.role === 'admin') perms = ALL_PERMS;
    else if (user.role === 'driver') perms = ['schedule'];
    else perms = user.permissions || ['orders'];
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, driver_id, permissions: perms } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authenticate, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id, username, role, permissions FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0] || req.user;
    let driver_id = null;
    if (user.role === 'driver') {
      const dResult = await pool.query('SELECT id FROM drivers WHERE user_id = $1', [user.id]);
      if (dResult.rows.length > 0) driver_id = dResult.rows[0].id;
    }
    const ALL_PERMS = ['orders','cleaners','extras','invoices','payments','reports','errors','schedule','settings'];
    let perms;
    if (user.role === 'admin') perms = ALL_PERMS;
    else if (user.role === 'driver') perms = ['schedule'];
    else perms = user.permissions || ['orders'];
    res.json({ user: { id: user.id, username: user.username, role: user.role, driver_id, permissions: perms } });
  } catch(e) {
    res.json({ user: req.user });
  }
});

// Orders routes
app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const { cleaner_id, start_date, end_date, limit = 1500, search } = req.query;
    let query = 'SELECT o.* FROM orders o';
    const params = [];
    const conditions = [];

    // Drivers only see their own orders
    if (req.user.role === 'driver') {
      params.push(req.user.username);
      conditions.push(`LOWER(o.staff_name) = $${params.length}`);
    }

    if (search) {
      query = `SELECT o.* FROM orders o LEFT JOIN cleaners c ON o.cleaner_id = c.id`;
      params.push('%' + search + '%', '%' + search + '%');
      conditions.push(`(o.order_num ILIKE $${params.length-1} OR c.name ILIKE $${params.length})`);
    }

    if (cleaner_id) {
      params.push(cleaner_id);
      conditions.push(`o.cleaner_id = $${params.length}`);
    }
    if (start_date) {
      params.push(start_date);
      conditions.push(`o.pickup_date >= $${params.length}`);
    }
    if (end_date) {
      params.push(end_date);
      conditions.push(`o.pickup_date <= $${params.length}`);
    }

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY o.pickup_date DESC, o.created_at DESC';
    params.push(limit);
    query += ` LIMIT $${params.length}`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders', authenticate, async (req, res) => {
  const { order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name, price_adjustment } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO orders (order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name, price_adjustment) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [order_num, cleaner_id, weight || 0, service_type || '24-hour', pickup_date, bag_color || 'White', extras || [], notes, staff_name, price_adjustment || 0]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders/import', authenticate, async (req, res) => {
  const { orders } = req.body;
  let imported = 0, skipped = 0;
  for (const o of orders) {
    try {
      await pool.query(
        `INSERT INTO orders (order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [o.order_num, o.cleaner_id, o.weight, o.service_type, o.pickup_date, o.bag_color || 'White', o.extras || [], o.notes || '', o.staff_name || '']
      );
      imported++;
    } catch (e) { skipped++; }
  }
  res.json({ imported, skipped });
});

app.put('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras, notes, staff_name, price_adjustment } = req.body;
  try {
    const result = await pool.query(
      `UPDATE orders SET order_num=$1, cleaner_id=$2, weight=$3, service_type=$4, pickup_date=$5, bag_color=$6, extras=$7, notes=$8, staff_name=$9, price_adjustment=$10, updated_at=CURRENT_TIMESTAMP WHERE id=$11 RETURNING *`,
      [order_num, cleaner_id, weight, service_type, pickup_date, bag_color, extras || [], notes, staff_name, price_adjustment || 0, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update order error:', err);
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

app.delete('/api/orders/clear-all', authenticate, adminOnly, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM orders');
    res.json({ deleted: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/export', authenticate, requirePerm('orders'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*, c.name as cleaner_name, c.rate as rate_per_lb, c.route 
      FROM orders o LEFT JOIN cleaners c ON o.cleaner_id = c.id 
      ORDER BY o.pickup_date DESC, o.created_at DESC
    `);
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });
    const orders = result.rows.map(o => {
      const extrasTotal = (o.extras || []).reduce((sum, id) => sum + parseFloat(extrasMap[id]?.price || 0), 0);
      const base = parseFloat(o.weight) * parseFloat(o.rate_per_lb || 0);
      return { ...o, extras: (o.extras || []).map(id => extrasMap[id]?.name).join(', '), extras_total: extrasTotal, total: base + extrasTotal + parseFloat(o.price_adjustment || 0) };
    });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/find-duplicates', authenticate, async (req, res) => {
  const { cleaner_id, start_date, end_date } = req.query;
  try {
    const result = await pool.query(`
      SELECT order_num, COUNT(*) as count FROM orders 
      WHERE cleaner_id = $1 AND pickup_date >= $2 AND pickup_date <= $3 
      GROUP BY order_num HAVING COUNT(*) > 1
    `, [cleaner_id, start_date, end_date]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Cleaners routes
app.get('/api/cleaners', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaners ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaners', authenticate, requirePerm('cleaners'), async (req, res) => {
  const { name, address, rate, route, min_weight, congestion_zone, congestion_rate } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO cleaners (name, address, rate, route, min_weight, congestion_zone, congestion_rate) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [name, address, rate, route || 'east', min_weight || 10, congestion_zone || false, congestion_rate || 5.00]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/cleaners/:id', authenticate, requirePerm('cleaners'), async (req, res) => {
  const { id } = req.params;
  const { name, address, rate, route, min_weight, congestion_zone, congestion_rate } = req.body;
  try {
    const result = await pool.query(
      'UPDATE cleaners SET name=$1, address=$2, rate=$3, route=$4, min_weight=$5, congestion_zone=$6, congestion_rate=$7 WHERE id=$8 RETURNING *',
      [name, address, rate, route, min_weight, congestion_zone || false, congestion_rate || 5.00, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cleaner not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaners/:id', authenticate, requirePerm('cleaners'), async (req, res) => {
  try {
    const orderCheck = await pool.query('SELECT COUNT(*) FROM orders WHERE cleaner_id = $1', [req.params.id]);
    if (parseInt(orderCheck.rows[0].count) > 0) return res.status(400).json({ error: 'Cannot delete cleaner with existing orders' });
    await pool.query('DELETE FROM cleaners WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Cleaner extras routes
app.get('/api/cleaner-extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaner_extras');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Routes matching frontend calls: /api/cleaners/:id/extras
app.get('/api/cleaners/:cleaner_id/extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cleaner_extras WHERE cleaner_id = $1', [req.params.cleaner_id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaners/:cleaner_id/extras', authenticate, requirePerm('cleaners'), async (req, res) => {
  const { extra_id, custom_price } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO cleaner_extras (cleaner_id, extra_id, custom_price) VALUES ($1, $2, $3) ON CONFLICT (cleaner_id, extra_id) DO UPDATE SET custom_price = $3 RETURNING *',
      [req.params.cleaner_id, extra_id, custom_price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaners/:cleaner_id/extras/:extra_id', authenticate, requirePerm('cleaners'), async (req, res) => {
  try {
    await pool.query('DELETE FROM cleaner_extras WHERE cleaner_id = $1 AND extra_id = $2', [req.params.cleaner_id, req.params.extra_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cleaner-extras', authenticate, requirePerm('cleaners'), async (req, res) => {
  const { cleaner_id, extra_id, custom_price } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO cleaner_extras (cleaner_id, extra_id, custom_price) VALUES ($1, $2, $3) ON CONFLICT (cleaner_id, extra_id) DO UPDATE SET custom_price = $3 RETURNING *',
      [cleaner_id, extra_id, custom_price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/cleaner-extras/:cleaner_id/:extra_id', authenticate, requirePerm('cleaners'), async (req, res) => {
  try {
    await pool.query('DELETE FROM cleaner_extras WHERE cleaner_id = $1 AND extra_id = $2', [req.params.cleaner_id, req.params.extra_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Extras routes
app.get('/api/extras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM extras ORDER BY category, name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/extras', authenticate, requirePerm('extras'), async (req, res) => {
  const { name, price, category } = req.body;
  try {
    const result = await pool.query('INSERT INTO extras (name, price, category) VALUES ($1, $2, $3) RETURNING *', [name, price, category || 'Other']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/extras/:id', authenticate, requirePerm('extras'), async (req, res) => {
  const { name, price, category } = req.body;
  try {
    const result = await pool.query('UPDATE extras SET name=$1, price=$2, category=$3 WHERE id=$4 RETURNING *', [name, price, category, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Extra not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/extras/:id', authenticate, requirePerm('extras'), async (req, res) => {
  try {
    await pool.query('DELETE FROM extras WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Settings routes
app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM settings');
    const settings = {};
    const stringKeys = ['companyName', 'companyAddress', 'storePhone', 'managerPhone'];
    result.rows.forEach(row => { 
      settings[row.key] = stringKeys.includes(row.key) ? row.value : parseFloat(row.value); 
    });
    if (!settings.companyName) settings.companyName = 'WEBSTER AVE LAUNDROMAT';
    if (!settings.companyAddress) settings.companyAddress = '1363 WEBSTER AVE, NEW YORK, NY 10456';
    if (!settings.storePhone) settings.storePhone = '929-263-1560';
    if (!settings.managerPhone) settings.managerPhone = '347-632-2024';
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/settings', authenticate, adminOnly, async (req, res) => {
  const { sameDayMult, defaultRate, companyName, companyAddress, storePhone, managerPhone } = req.body;
  try {
    if (sameDayMult !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['sameDayMult', sameDayMult.toString()]);
    if (defaultRate !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['defaultRate', defaultRate.toString()]);
    if (companyName !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['companyName', companyName]);
    if (companyAddress !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['companyAddress', companyAddress]);
    if (storePhone !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['storePhone', storePhone]);
    if (managerPhone !== undefined) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['managerPhone', managerPhone]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Reports routes
app.get('/api/reports/invoice', authenticate, requirePerm('invoices'), async (req, res) => {
  const { cleaner_id, start_date, end_date } = req.query;
  if (!cleaner_id || !start_date || !end_date) return res.status(400).json({ error: 'cleaner_id, start_date, and end_date required' });

  try {
    const cleanerResult = await pool.query('SELECT * FROM cleaners WHERE id = $1', [cleaner_id]);
    const cleaner = cleanerResult.rows[0];
    
    // If end_date is a Saturday, include following Sunday's orders in this week's invoice
    // (Sunday orders are data entry mistakes and belong to the prior Mon-Sat week)
    const endDate = new Date(end_date + 'T12:00:00');
    const endDay = endDate.getDay(); // 0=Sun,6=Sat
    let adjustedEnd = end_date;
    if (endDay === 6) { // Saturday - include Sunday
      const sun = new Date(endDate);
      sun.setDate(sun.getDate() + 1);
      adjustedEnd = sun.toISOString().split('T')[0];
    }

    const ordersResult = await pool.query(
      `SELECT o.*, c.name as cleaner_name, c.rate as cleaner_rate, c.min_weight, c.congestion_zone, c.congestion_rate
       FROM orders o JOIN cleaners c ON o.cleaner_id = c.id 
       WHERE o.cleaner_id = $1 AND o.pickup_date >= $2 AND o.pickup_date <= $3 ORDER BY o.pickup_date, o.order_num`,
      [cleaner_id, start_date, adjustedEnd]
    );

    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });

    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras WHERE cleaner_id = $1', [cleaner_id]);
    const cleanerExtrasMap = {};
    cleanerExtrasResult.rows.forEach(ce => { cleanerExtrasMap[ce.extra_id] = parseFloat(ce.custom_price); });

    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });

    const uniquePickupDates = new Set();

    const orderNums = ordersResult.rows.map(o => parseInt(o.order_num.replace(/\D/g, ''))).filter(n => !isNaN(n)).sort((a, b) => a - b);
    const sequenceWarnings = [];
    for (let i = 1; i < orderNums.length; i++) {
      const gap = orderNums[i] - orderNums[i - 1];
      if (gap > 50 || gap < 0) {
        sequenceWarnings.push({ from: orderNums[i - 1], to: orderNums[i], gap });
      }
    }

    const orders = ordersResult.rows.map(o => {
      const minWeight = parseFloat(o.min_weight) || 10;
      const billedWeight = Math.max(parseFloat(o.weight), parseFloat(o.weight) > 0 ? minWeight : 0);
      const rate = parseFloat(o.cleaner_rate);
      const mult = o.service_type === 'same-day' ? settings.sameDayMult : 1;
      const base = billedWeight * rate * mult;

      const extrasTotal = (o.extras || []).reduce((sum, id) => {
        const customPrice = cleanerExtrasMap[id];
        const defaultPrice = extrasMap[id]?.price || 0;
        return sum + (customPrice !== undefined ? customPrice : parseFloat(defaultPrice));
      }, 0);

      const extrasFormatted = (o.extras || []).map(id => {
        const ex = extrasMap[id];
        const customPrice = cleanerExtrasMap[id];
        const price = customPrice !== undefined ? customPrice : parseFloat(ex?.price || 0);
        return ex ? ex.name : null;
      }).filter(Boolean).join(', ');

      if (o.pickup_date) {
        uniquePickupDates.add(o.pickup_date.toISOString().split('T')[0]);
      }

      return { ...o, total: base + extrasTotal + parseFloat(o.price_adjustment || 0), extras_formatted: extrasFormatted, billed_weight: billedWeight };
    });

    const ordersTotal = orders.reduce((sum, o) => sum + o.total, 0);

    let congestionSurcharge = 0;
    let congestionDays = 0;
    if (cleaner && cleaner.congestion_zone) {
      congestionDays = uniquePickupDates.size;
      congestionSurcharge = congestionDays * parseFloat(cleaner.congestion_rate || 5);
    }

    const grandTotal = ordersTotal + congestionSurcharge;

    res.json({ 
      orders, 
      ordersTotal,
      congestionZone: cleaner?.congestion_zone || false,
      congestionRate: parseFloat(cleaner?.congestion_rate || 5),
      congestionDays,
      congestionSurcharge,
      grandTotal, 
      sequenceWarnings 
    });
  } catch (err) {
    console.error('Invoice report error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/invoices-all', authenticate, requirePerm('invoices'), async (req, res) => {
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date and end_date required' });

  try {
    const cleanersResult = await pool.query('SELECT * FROM cleaners ORDER BY name');
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });

    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras');
    const cleanerExtrasMap = {};
    cleanerExtrasResult.rows.forEach(ce => {
      if (!cleanerExtrasMap[ce.cleaner_id]) cleanerExtrasMap[ce.cleaner_id] = {};
      cleanerExtrasMap[ce.cleaner_id][ce.extra_id] = parseFloat(ce.custom_price);
    });

    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });

    const invoices = [];

    // If end_date is Saturday, include following Sunday (Sunday orders belong to prior week)
    const endDate2 = new Date(end_date + 'T12:00:00');
    const endDay2 = endDate2.getDay();
    let adjustedEnd2 = end_date;
    if (endDay2 === 6) {
      const sun = new Date(endDate2);
      sun.setDate(sun.getDate() + 1);
      adjustedEnd2 = sun.toISOString().split('T')[0];
    }

    for (const cleaner of cleanersResult.rows) {
      const ordersResult = await pool.query(
        `SELECT * FROM orders WHERE cleaner_id = $1 AND pickup_date >= $2 AND pickup_date <= $3 ORDER BY pickup_date, order_num`,
        [cleaner.id, start_date, adjustedEnd2]
      );

      if (ordersResult.rows.length === 0) continue;

      const cleanerPrices = cleanerExtrasMap[cleaner.id] || {};
      const uniquePickupDates = new Set();

      const orders = ordersResult.rows.map(o => {
        const minWeight = parseFloat(cleaner.min_weight) || 10;
        const billedWeight = Math.max(parseFloat(o.weight), parseFloat(o.weight) > 0 ? minWeight : 0);
        const rate = parseFloat(cleaner.rate);
        const mult = o.service_type === 'same-day' ? settings.sameDayMult : 1;
        const base = billedWeight * rate * mult;

        const extrasTotal = (o.extras || []).reduce((sum, id) => {
          const customPrice = cleanerPrices[id];
          const defaultPrice = extrasMap[id]?.price || 0;
          return sum + (customPrice !== undefined ? customPrice : parseFloat(defaultPrice));
        }, 0);

        const extrasFormatted = (o.extras || []).map(id => {
          const ex = extrasMap[id];
          const customPrice = cleanerPrices[id];
          const price = customPrice !== undefined ? customPrice : parseFloat(ex?.price || 0);
          return ex ? ex.name : null;
        }).filter(Boolean).join(', ');

        if (o.pickup_date) {
          uniquePickupDates.add(o.pickup_date.toISOString().split('T')[0]);
        }

        return { ...o, total: base + extrasTotal + parseFloat(o.price_adjustment || 0), extras_formatted: extrasFormatted };
      });

      const ordersTotal = orders.reduce((sum, o) => sum + o.total, 0);

      let congestionSurcharge = 0;
      let congestionDays = 0;
      if (cleaner.congestion_zone) {
        congestionDays = uniquePickupDates.size;
        congestionSurcharge = congestionDays * parseFloat(cleaner.congestion_rate || 5);
      }

      const grandTotal = ordersTotal + congestionSurcharge;

      invoices.push({ 
        cleaner, 
        orders, 
        ordersTotal,
        congestionZone: cleaner.congestion_zone,
        congestionRate: parseFloat(cleaner.congestion_rate || 5),
        congestionDays,
        congestionSurcharge,
        grandTotal 
      });
    }

    res.json({ invoices });
  } catch (err) {
    console.error('All invoices error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/daily', authenticate, requirePerm('reports'), async (req, res) => {
  const { start_date, end_date } = req.query;
  try {
    const result = await pool.query(`
      SELECT pickup_date, c.route, COUNT(*) as order_count, SUM(o.weight) as total_weight
      FROM orders o JOIN cleaners c ON o.cleaner_id = c.id
      WHERE o.pickup_date >= $1 AND o.pickup_date <= $2
      GROUP BY o.pickup_date, c.route ORDER BY o.pickup_date
    `, [start_date, end_date]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/daily-stats', authenticate, requirePerm('reports'), async (req, res) => {
  const { start_date, end_date } = req.query;
  try {
    const cleaners = await pool.query('SELECT * FROM cleaners');
    const cleanerMap = {};
    cleaners.rows.forEach(c => { cleanerMap[c.id] = c; });

    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });

    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras');
    const cleanerExtrasMap = {};
    cleanerExtrasResult.rows.forEach(ce => {
      if (!cleanerExtrasMap[ce.cleaner_id]) cleanerExtrasMap[ce.cleaner_id] = {};
      cleanerExtrasMap[ce.cleaner_id][ce.extra_id] = parseFloat(ce.custom_price);
    });

    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });

    const ordersResult = await pool.query(
      'SELECT * FROM orders WHERE pickup_date >= $1 AND pickup_date <= $2',
      [start_date, end_date]
    );

    let totalOrders = 0, totalWeight = 0, totalAmount = 0;
    let eastOrders = 0, eastAmount = 0, westOrders = 0, westAmount = 0;
    let sameDayOrders = 0, sameDayWeight = 0, twentyFourOrders = 0, twentyFourWeight = 0;
    const cleanerStats = {};
    const dailyStats = {};
    const cleanerPickupDates = {};

    for (const o of ordersResult.rows) {
      const cleaner = cleanerMap[o.cleaner_id];
      if (!cleaner) continue;

      const cleanerPrices = cleanerExtrasMap[o.cleaner_id] || {};
      const minWeight = parseFloat(cleaner.min_weight) || 10;
      const billedWeight = Math.max(parseFloat(o.weight), parseFloat(o.weight) > 0 ? minWeight : 0);
      const mult = o.service_type === 'same-day' ? settings.sameDayMult : 1;
      const base = billedWeight * parseFloat(cleaner.rate) * mult;
      const extrasTotal = (o.extras || []).reduce((sum, id) => {
        const customPrice = cleanerPrices[id];
        return sum + (customPrice !== undefined ? customPrice : parseFloat(extrasMap[id]?.price || 0));
      }, 0);
      const orderTotal = base + extrasTotal + parseFloat(o.price_adjustment || 0);

      totalOrders++;
      totalWeight += parseFloat(o.weight);
      totalAmount += orderTotal;

      if (cleaner.route === 'east') { eastOrders++; eastAmount += orderTotal; }
      else { westOrders++; westAmount += orderTotal; }

      if (o.service_type === 'same-day') { sameDayOrders++; sameDayWeight += parseFloat(o.weight); }
      else { twentyFourOrders++; twentyFourWeight += parseFloat(o.weight); }

      if (!cleanerStats[cleaner.id]) cleanerStats[cleaner.id] = { name: cleaner.name, route: cleaner.route, orders: 0, weight: 0, amount: 0, congestion_zone: cleaner.congestion_zone, congestion_rate: parseFloat(cleaner.congestion_rate || 5) };
      cleanerStats[cleaner.id].orders++;
      cleanerStats[cleaner.id].weight += parseFloat(o.weight);
      cleanerStats[cleaner.id].amount += orderTotal;

      if (cleaner.congestion_zone && o.pickup_date) {
        if (!cleanerPickupDates[cleaner.id]) cleanerPickupDates[cleaner.id] = new Set();
        cleanerPickupDates[cleaner.id].add(o.pickup_date.toISOString().split('T')[0]);
      }

      const dateKey = o.pickup_date.toISOString().split('T')[0];
      if (!dailyStats[dateKey]) dailyStats[dateKey] = { date: dateKey, orders: 0, weight: 0, amount: 0, eastOrders: 0, eastAmount: 0, westOrders: 0, westAmount: 0 };
      dailyStats[dateKey].orders++;
      dailyStats[dateKey].weight += parseFloat(o.weight);
      dailyStats[dateKey].amount += orderTotal;
      if (cleaner.route === 'east') { dailyStats[dateKey].eastOrders++; dailyStats[dateKey].eastAmount += orderTotal; }
      else { dailyStats[dateKey].westOrders++; dailyStats[dateKey].westAmount += orderTotal; }
    }

    let totalCongestion = 0;
    for (const cleanerId in cleanerPickupDates) {
      const cleaner = cleanerMap[cleanerId];
      const days = cleanerPickupDates[cleanerId].size;
      const charge = days * parseFloat(cleaner.congestion_rate || 5);
      totalCongestion += charge;
      if (cleanerStats[cleanerId]) {
        cleanerStats[cleanerId].congestion_days = days;
        cleanerStats[cleanerId].congestion_charge = charge;
      }
    }

    res.json({
      totals: {
        total_orders: totalOrders, total_weight: totalWeight, total_amount: totalAmount,
        total_congestion: totalCongestion, grand_total: totalAmount + totalCongestion,
        east_orders: eastOrders, east_amount: eastAmount, west_orders: westOrders, west_amount: westAmount,
        same_day_orders: sameDayOrders, same_day_weight: sameDayWeight,
        twenty_four_hour_orders: twentyFourOrders, twenty_four_hour_weight: twentyFourWeight
      },
      cleanerBreakdown: Object.values(cleanerStats).sort((a, b) => b.amount - a.amount),
      dailyBreakdown: Object.values(dailyStats).sort((a, b) => a.date.localeCompare(b.date))
    });
  } catch (err) {
    console.error('Daily stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Invoice tracking routes
app.get('/api/invoice-tracking', authenticate, requirePerm('invoices'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT it.*, c.name as cleaner_name, c.route 
      FROM invoice_tracking it JOIN cleaners c ON it.cleaner_id = c.id 
      ORDER BY it.week_start DESC, c.name
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/invoice-tracking/summary', authenticate, requirePerm('invoices'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.name as cleaner_name, c.route,
        SUM(it.invoice_amount) as total_invoiced,
        SUM(it.amount_paid) as total_paid,
        SUM(it.invoice_amount - it.amount_paid) as total_due
      FROM invoice_tracking it JOIN cleaners c ON it.cleaner_id = c.id
      GROUP BY c.id, c.name, c.route ORDER BY c.name
    `);
    const overall = await pool.query(`
      SELECT SUM(invoice_amount) as total_invoiced, SUM(amount_paid) as total_paid, SUM(invoice_amount - amount_paid) as total_due
      FROM invoice_tracking
    `);
    res.json({ cleaners: result.rows, overall: overall.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoice-tracking/generate-week', authenticate, requirePerm('invoices'), async (req, res) => {
  const { week_start, week_end } = req.body;
  try {
    const cleaners = await pool.query('SELECT * FROM cleaners');
    const extrasResult = await pool.query('SELECT * FROM extras');
    const extrasMap = {};
    extrasResult.rows.forEach(e => { extrasMap[e.id] = e; });

    const cleanerExtrasResult = await pool.query('SELECT * FROM cleaner_extras');
    const cleanerExtrasMap = {};
    cleanerExtrasResult.rows.forEach(ce => {
      if (!cleanerExtrasMap[ce.cleaner_id]) cleanerExtrasMap[ce.cleaner_id] = {};
      cleanerExtrasMap[ce.cleaner_id][ce.extra_id] = parseFloat(ce.custom_price);
    });

    const settingsResult = await pool.query('SELECT * FROM settings');
    const settings = {};
    settingsResult.rows.forEach(row => { settings[row.key] = parseFloat(row.value); });

    let generated = 0;
    for (const cleaner of cleaners.rows) {
      const orders = await pool.query(
        'SELECT * FROM orders WHERE cleaner_id = $1 AND pickup_date >= $2 AND pickup_date <= $3',
        [cleaner.id, week_start, week_end]
      );
      if (orders.rows.length === 0) continue;

      const cleanerPrices = cleanerExtrasMap[cleaner.id] || {};
      const uniquePickupDates = new Set();

      let total = 0;
      for (const o of orders.rows) {
        const minWeight = parseFloat(cleaner.min_weight) || 10;
        const billedWeight = Math.max(parseFloat(o.weight), parseFloat(o.weight) > 0 ? minWeight : 0);
        const base = billedWeight * parseFloat(cleaner.rate) * (o.service_type === 'same-day' ? settings.sameDayMult : 1);
        const extrasTotal = (o.extras || []).reduce((sum, id) => {
          const customPrice = cleanerPrices[id];
          return sum + (customPrice !== undefined ? customPrice : parseFloat(extrasMap[id]?.price || 0));
        }, 0);
        total += base + extrasTotal + parseFloat(o.price_adjustment || 0);
        
        if (o.pickup_date) {
          uniquePickupDates.add(o.pickup_date.toISOString().split('T')[0]);
        }
      }

      if (cleaner.congestion_zone) {
        const congestionDays = uniquePickupDates.size;
        total += congestionDays * parseFloat(cleaner.congestion_rate || 5);
      }

      await pool.query(
        `INSERT INTO invoice_tracking (cleaner_id, week_start, week_end, invoice_amount) 
         VALUES ($1, $2, $3, $4) ON CONFLICT (cleaner_id, week_start) DO UPDATE SET invoice_amount = $4`,
        [cleaner.id, week_start, week_end, total]
      );
      generated++;
    }
    res.json({ generated });
  } catch (err) {
    console.error('Generate week error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/invoice-tracking/:id', authenticate, requirePerm('invoices'), async (req, res) => {
  const { amount_paid, paid_date, status, notes } = req.body;
  try {
    const result = await pool.query(
      'UPDATE invoice_tracking SET amount_paid=$1, paid_date=$2, status=$3, notes=$4 WHERE id=$5 RETURNING *',
      [amount_paid, paid_date, status, notes, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/invoice-tracking/:id', authenticate, requirePerm('invoices'), async (req, res) => {
  try {
    await pool.query('DELETE FROM invoice_tracking WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Export database
app.get('/api/export-database', authenticate, adminOnly, async (req, res) => {
  try {
    const [orders, cleaners, extras, cleaner_extras, settings, invoice_tracking] = await Promise.all([
      pool.query('SELECT * FROM orders ORDER BY pickup_date DESC'),
      pool.query('SELECT * FROM cleaners ORDER BY name'),
      pool.query('SELECT * FROM extras ORDER BY name'),
      pool.query('SELECT * FROM cleaner_extras'),
      pool.query('SELECT * FROM settings'),
      pool.query('SELECT * FROM invoice_tracking ORDER BY week_start DESC')
    ]);
    res.json({
      orders: orders.rows,
      cleaners: cleaners.rows,
      extras: extras.rows,
      cleaner_extras: cleaner_extras.rows,
      settings: settings.rows,
      invoice_tracking: invoice_tracking.rows
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Auto-delete old orders (90 days)
async function cleanupOldOrders() {
  try {
    const result = await pool.query("DELETE FROM orders WHERE pickup_date < CURRENT_DATE - INTERVAL '90 days'");
    if (result.rowCount > 0) console.log('Cleaned up', result.rowCount, 'old orders');
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}

// === Mount Schedule Routes (Driver Scheduling & Pay) ===
app.use('/api', scheduleRoutes(pool, authenticate, adminOnly));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Serve frontend for all non-API routes
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  const indexPath = path.join(__dirname, 'public', 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      res.status(200).send('Webster Orders - Backend running. Deploy index.html to public/ folder.');
    }
  });
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    cleanupOldOrders();
    setInterval(cleanupOldOrders, 24 * 60 * 60 * 1000);
  });
});