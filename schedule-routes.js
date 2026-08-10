// schedule-routes.js - Shift-based scheduling system
const express = require('express');

module.exports = function(pool, authenticate, adminOnly) {
  const router = express.Router();

  // Middleware: can manage schedule (admin or driver manager)
  const canManageSchedule = async (req, res, next) => {
    if (req.user.role === 'admin') return next();
    try {
      const result = await pool.query('SELECT permissions FROM users WHERE id = $1', [req.user.id]);
      const perms = result.rows[0]?.permissions || [];
      if (perms.includes('manage_schedule')) return next();
      return res.status(403).json({ error: 'Not authorized' });
    } catch (err) { return res.status(500).json({ error: 'Server error' }); }
  };

  // =============================================
  // DRIVERS CRUD
  // =============================================
  
  router.get('/drivers', authenticate, async (req, res) => {
    try {
      const includeTerminated = req.query.include_terminated === 'true';
      const query = includeTerminated ? 'SELECT * FROM drivers ORDER BY name' : "SELECT * FROM drivers WHERE status != 'terminated' ORDER BY name";
      const { rows } = await pool.query(query);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  router.post('/drivers', authenticate, canManageSchedule, async (req, res) => {
    const { name, phone, email, hourly_rate, day_rate, pay_type, payment_method, dl_number, dl_expiration, address, ssn, zelle_info, notes } = req.body;
    try {
      const result = await pool.query(
        `INSERT INTO drivers (name, phone, email, hourly_rate, day_rate, pay_type, payment_method, dl_number, dl_expiration, address, ssn, zelle_info, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
        [name, phone, email, hourly_rate || 16.50, day_rate, pay_type || 'hourly', payment_method || 'cash', dl_number, dl_expiration, address, ssn, zelle_info, notes]
      );
      res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
  });

  router.put('/drivers/:id', authenticate, canManageSchedule, async (req, res) => {
    const { name, phone, email, hourly_rate, day_rate, pay_type, payment_method, status, dl_number, dl_expiration, address, ssn, zelle_info, notes } = req.body;
    try {
      const result = await pool.query(
        `UPDATE drivers SET name=$1, phone=$2, email=$3, hourly_rate=$4, day_rate=$5, pay_type=$6, payment_method=$7, status=$8, dl_number=$9, dl_expiration=$10, address=$11, ssn=$12, zelle_info=$13, notes=$14 WHERE id=$15 RETURNING *`,
        [name, phone, email, hourly_rate, day_rate, pay_type, payment_method, status || 'active', dl_number, dl_expiration, address, ssn, zelle_info, notes, req.params.id]
      );
      res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  router.delete('/drivers/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { force } = req.query;
      if (force === 'true') {
        // Permanent delete - remove assignments first
        await pool.query('DELETE FROM shift_assignments WHERE driver_id = $1', [req.params.id]);
        await pool.query('DELETE FROM shift_requests WHERE driver_name IN (SELECT name FROM drivers WHERE id = $1)', [req.params.id]);
        await pool.query('UPDATE users SET user_id = NULL WHERE id IN (SELECT user_id FROM drivers WHERE id = $1)', [req.params.id]);
        await pool.query('DELETE FROM drivers WHERE id = $1', [req.params.id]);
      } else {
        await pool.query("UPDATE drivers SET status = 'terminated' WHERE id = $1", [req.params.id]);
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });


  // =============================================
  // USERS CRUD (Admin only)
  // =============================================

  router.get('/users', authenticate, adminOnly, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT id, username, role, plain_password, permissions, created_at FROM users ORDER BY username');
      res.json(rows);
    } catch (err) { console.error('Get users error:', err); res.status(500).json({ error: 'Server error' }); }
  });

  router.post('/users', authenticate, adminOnly, async (req, res) => {
    try {
      const { username, password, role, driver_id, permissions } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const validRoles = ['admin', 'attendant', 'driver'];
      const userRole = validRoles.includes(role) ? role : 'attendant';
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash(password, 10);
      const userPerms = JSON.stringify(permissions || ['orders']);
      const { rows } = await pool.query(
        'INSERT INTO users (username, password, role, plain_password, permissions) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role, permissions, created_at',
        [username.toLowerCase(), hash, userRole, password, userPerms]
      );
      if (userRole === 'driver' && driver_id) {
        await pool.query('UPDATE drivers SET user_id = $1 WHERE id = $2', [rows[0].id, driver_id]);
      }
      res.json(rows[0]);
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Create user error:', err); res.status(500).json({ error: 'Server error' });
    }
  });

  router.put('/users/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { username, password, role, driver_id, permissions } = req.body;
      const validRoles = ['admin', 'attendant', 'driver'];
      const userId = req.params.id;
      const userPerms = permissions ? JSON.stringify(permissions) : undefined;
      let rows;
      if (password) {
        const bcrypt = require('bcryptjs');
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
          `UPDATE users SET username = COALESCE($1, username), password = $2, role = COALESCE($3, role), 
           plain_password = $4, permissions = COALESCE($5::jsonb, permissions) WHERE id = $6 
           RETURNING id, username, role, permissions, created_at`,
          [username ? username.toLowerCase() : undefined, hash, validRoles.includes(role) ? role : undefined, password, userPerms || null, userId]
        );
        rows = result.rows;
      } else {
        const result = await pool.query(
          `UPDATE users SET username = COALESCE($1, username), role = COALESCE($2, role),
           permissions = COALESCE($3::jsonb, permissions) WHERE id = $4 
           RETURNING id, username, role, permissions, created_at`,
          [username ? username.toLowerCase() : undefined, validRoles.includes(role) ? role : undefined, userPerms || null, userId]
        );
        rows = result.rows;
      }
      if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
      if (role === 'driver' && driver_id) {
        await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
        await pool.query('UPDATE drivers SET user_id = $1 WHERE id = $2', [userId, driver_id]);
      } else if (role !== 'driver') {
        await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
      }
      res.json(rows[0]);
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Update user error:', err); res.status(500).json({ error: 'Server error' });
    }
  });

  router.delete('/users/:id', authenticate, adminOnly, async (req, res) => {
    try {
      if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
      await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [req.params.id]);
      await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) { console.error('Delete user error:', err); res.status(500).json({ error: 'Server error' }); }
  });

  // =============================================
  // SHIFTS DEFINITION (Admin only for create/edit/delete)
  // =============================================

  router.get('/shifts', authenticate, async (req, res) => {
    try {
      const result = await pool.query('SELECT * FROM shifts WHERE active = true ORDER BY sort_order, id');
      res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  router.post('/shifts', authenticate, adminOnly, async (req, res) => {
    const { name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days, category, sort_order, notes, day_of_week } = req.body;
    try {
      const result = await pool.query(
        `INSERT INTO shifts (name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days, category, sort_order, notes, day_of_week)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [name, start_time || null, end_time || null, hours || null, base_pay || null, heavy_pay || null, heavy_days || '', category || 'regular', sort_order || 99, notes || null, day_of_week || null]
      );
      res.json(result.rows[0]);
    } catch (err) { console.error('Create shift error:', err); res.status(500).json({ error: err.message }); }
  });

  router.put('/shifts/:id', authenticate, adminOnly, async (req, res) => {
    const { name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days, category, sort_order, notes, day_of_week } = req.body;
    try {
      const result = await pool.query(
        `UPDATE shifts SET name=$1, start_time=$2, end_time=$3, hours=$4, base_pay=$5, heavy_pay=$6, heavy_days=$7, category=$8, sort_order=$9, notes=$10, day_of_week=$11 WHERE id=$12 RETURNING *`,
        [name, start_time || null, end_time || null, hours || null, base_pay || null, heavy_pay || null, heavy_days || '', category, sort_order, notes || null, day_of_week || null, req.params.id]
      );
      res.json(result.rows[0]);
    } catch (err) { console.error('Update shift error:', err); res.status(500).json({ error: err.message }); }
  });

  router.delete('/shifts/:id', authenticate, adminOnly, async (req, res) => {
    try {
      await pool.query('UPDATE shifts SET active = false WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // =============================================
  // SHIFT ASSIGNMENTS (Admin + Manager)
  // =============================================

  // Get assignments for a date range
  router.get('/shift-assignments', authenticate, async (req, res) => {
    const { start_date, end_date } = req.query;
    try {
      let query = `SELECT sa.*, s.name as shift_name, s.start_time, s.end_time, s.base_pay, s.heavy_pay, s.heavy_days, s.category, s.hours, s.notes as shift_notes,
        d.name as driver_name FROM shift_assignments sa
        JOIN shifts s ON sa.shift_id = s.id
        LEFT JOIN drivers d ON sa.driver_id = d.id`;
      const params = [];
      if (start_date && end_date) {
        params.push(start_date, end_date);
        query += ' WHERE sa.work_date >= $1 AND sa.work_date <= $2';
      }
      query += ' ORDER BY sa.work_date, s.sort_order';
      const result = await pool.query(query, params);
      res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Assign driver to shift
  router.post('/shift-assignments', authenticate, canManageSchedule, async (req, res) => {
    const { shift_id, driver_id, work_date, pay_override, notes } = req.body;
    try {
      // Check if already assigned
      const existing = await pool.query('SELECT * FROM shift_assignments WHERE shift_id = $1 AND work_date = $2', [shift_id, work_date]);
      if (existing.rows.length > 0) {
        // Update existing
        const newStatus = driver_id ? 'assigned' : 'open';
        const result = await pool.query(
          driver_id ? 
            'UPDATE shift_assignments SET driver_id=$1, pay_override=$2, notes=$3, status=$4 WHERE shift_id=$5 AND work_date=$6 RETURNING *' :
            'UPDATE shift_assignments SET driver_id=NULL, pay_override=NULL, notes=$1, status=$2, admin_confirmed=false WHERE shift_id=$3 AND work_date=$4 RETURNING *',
          driver_id ? [driver_id, pay_override || null, notes, newStatus, shift_id, work_date] : [notes, 'open', shift_id, work_date]
        );
        return res.json(result.rows[0]);
      }
      const result = await pool.query(
        'INSERT INTO shift_assignments (shift_id, driver_id, work_date, pay_override, notes) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [shift_id, driver_id, work_date, pay_override || null, notes]
      );
      res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
  });

  // Remove assignment
  router.delete('/shift-assignments/:id', authenticate, canManageSchedule, async (req, res) => {
    try {
      // Check admin_confirmed - only admin can remove locked
      const existing = await pool.query('SELECT admin_confirmed FROM shift_assignments WHERE id = $1', [req.params.id]);
      if (existing.rows.length > 0 && existing.rows[0].admin_confirmed && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'This assignment is locked by admin' });
      }
      await pool.query('DELETE FROM shift_assignments WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Lock/confirm assignment (admin only)
  router.put('/shift-assignments/:id/confirm', authenticate, adminOnly, async (req, res) => {
    try {
      const result = await pool.query(
        'UPDATE shift_assignments SET admin_confirmed = $1 WHERE id = $2 RETURNING *',
        [req.body.confirmed !== false, req.params.id]
      );
      res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Bulk generate empty assignments for a week (admin/manager)
  router.post('/shift-assignments/generate-week', authenticate, canManageSchedule, async (req, res) => {
    const { start_date } = req.body;
    try {
      const shifts = await pool.query('SELECT * FROM shifts WHERE active = true ORDER BY sort_order');
      const startDt = new Date(start_date + 'T12:00:00');
      let created = 0;
      
      for (let dayOffset = 0; dayOffset < 6; dayOffset++) { // Mon-Sat
        const dt = new Date(startDt);
        dt.setDate(startDt.getDate() + dayOffset);
        const dateStr = dt.toISOString().split('T')[0];
        const dow = dt.getDay(); // 0=Sun, 1=Mon...5=Fri, 6=Sat
        
        for (const shift of shifts.rows) {
          // Skip if shift is day-specific and doesn't match
          if (shift.day_of_week !== null && shift.day_of_week !== dow) continue;
          // Skip Laundry Day shifts on wrong days
          if (shift.name === 'Laundry Day Fri' && dow !== 5) continue;
          if (shift.name === 'Laundry Day Sat' && dow !== 6) continue;
          
          // Check if already exists - never overwrite assigned drivers
          const exists = await pool.query('SELECT id, driver_id FROM shift_assignments WHERE shift_id = $1 AND work_date = $2', [shift.id, dateStr]);
          if (exists.rows.length === 0) {
            await pool.query('INSERT INTO shift_assignments (shift_id, work_date, status) VALUES ($1, $2, $3)', [shift.id, dateStr, 'open']);
            created++;
          }
          // If exists but has no driver, make sure status is 'open'
          else if (!exists.rows[0].driver_id) {
            await pool.query("UPDATE shift_assignments SET status = 'open' WHERE id = $1", [exists.rows[0].id]);
          }
        }
      }
      res.json({ success: true, created });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
  });

  // =============================================
  // SHIFT REQUESTS (Drivers can create, Admin/Manager approve)
  // =============================================

  router.get('/shift-requests', authenticate, async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT sr.*, s.name as shift_name, s.start_time, s.end_time, s.base_pay, s.category
        FROM shift_requests sr JOIN shifts s ON sr.shift_id = s.id
        ORDER BY sr.work_date ASC, sr.created_at ASC LIMIT 200
      `);
      res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Driver requests a shift
  router.post('/shift-requests', authenticate, async (req, res) => {
    const { shift_id, work_date, driver_name, notes } = req.body;
    try {
      const result = await pool.query(
        'INSERT INTO shift_requests (shift_id, driver_name, work_date, notes) VALUES ($1,$2,$3,$4) RETURNING *',
        [shift_id, driver_name || req.user.username, work_date, notes]
      );
      res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Approve/deny request (admin/manager)
  router.put('/shift-requests/:id', authenticate, canManageSchedule, async (req, res) => {
    const { status } = req.body; // 'approved' or 'denied'
    try {
      const request = await pool.query('SELECT * FROM shift_requests WHERE id = $1', [req.params.id]);
      if (request.rows.length === 0) return res.status(404).json({ error: 'Not found' });
      
      const sr = request.rows[0];
      if (status === 'denied') {
        // Denied requests are removed entirely
        await pool.query('DELETE FROM shift_requests WHERE id = $1', [req.params.id]);
        return res.json({ success: true, removed: true });
      }
      await pool.query('UPDATE shift_requests SET status = $1 WHERE id = $2', [status, req.params.id]);
      
      // If approved, assign the driver
      if (status === 'approved') {
        // Find driver by name - try exact, then partial match
        let driver = await pool.query("SELECT id, name FROM drivers WHERE LOWER(name) = LOWER($1) AND status = 'active' LIMIT 1", [sr.driver_name]);
        if (driver.rows.length === 0) {
          driver = await pool.query("SELECT id, name FROM drivers WHERE LOWER(name) LIKE LOWER($1) AND status = 'active' LIMIT 1", ['%' + sr.driver_name + '%']);
        }
        if (driver.rows.length > 0) {
          await pool.query(
            'INSERT INTO shift_assignments (shift_id, driver_id, work_date, status) VALUES ($1,$2,$3,$4) ON CONFLICT (shift_id, work_date) DO UPDATE SET driver_id=$2, status=$4',
            [sr.shift_id, driver.rows[0].id, sr.work_date, 'assigned']
          );
          // Remove the request - assignment now shows on the grid
          await pool.query('DELETE FROM shift_requests WHERE id = $1', [req.params.id]);
          // Also remove any competing pending requests for the same slot
          await pool.query("DELETE FROM shift_requests WHERE shift_id = $1 AND work_date = $2 AND status = 'pending'", [sr.shift_id, sr.work_date]);
          res.json({ success: true, assigned: driver.rows[0].name });
        } else {
          // No driver found - still mark approved but warn admin
          res.json({ success: true, warning: 'No driver named "' + sr.driver_name + '" found in drivers list. Request approved but not assigned to schedule. Add this driver first.' });
        }
      } else {
        res.json({ success: true });
      }
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // Delete handled requests (admin only)
  router.delete('/shift-requests/handled', authenticate, adminOnly, async (req, res) => {
    try {
      const result = await pool.query("DELETE FROM shift_requests WHERE status != 'pending' RETURNING id");
      res.json({ success: true, deleted: result.rows.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Delete single request (admin only)
  router.delete('/shift-requests/:id', authenticate, adminOnly, async (req, res) => {
    try {
      await pool.query('DELETE FROM shift_requests WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // =============================================
  // PAY SUMMARY
  // =============================================

  router.get('/shift-pay-summary', authenticate, canManageSchedule, async (req, res) => {
    const { start_date, end_date } = req.query;
    try {
      const result = await pool.query(`
        SELECT d.name as driver_name, sa.work_date, s.name as shift_name, s.base_pay, s.heavy_pay, s.heavy_days, sa.pay_override,
          EXTRACT(DOW FROM sa.work_date) as dow
        FROM shift_assignments sa
        JOIN shifts s ON sa.shift_id = s.id
        JOIN drivers d ON sa.driver_id = d.id
        WHERE sa.work_date >= $1 AND sa.work_date <= $2 AND sa.driver_id IS NOT NULL
        ORDER BY d.name, sa.work_date
      `, [start_date, end_date]);
      
      // Calculate pay per assignment
      const rows = result.rows.map(r => {
        let pay = parseFloat(r.pay_override || 0);
        if (!pay) {
          pay = parseFloat(r.base_pay || 0);
          if (r.heavy_pay && r.heavy_days) {
            const heavyDays = r.heavy_days.split(',').map(d => parseInt(d.trim()));
            if (heavyDays.includes(parseInt(r.dow))) pay = parseFloat(r.heavy_pay);
          }
        }
        return { ...r, calculated_pay: pay };
      });
      
      // Group by driver
      const byDriver = {};
      rows.forEach(r => {
        if (!byDriver[r.driver_name]) byDriver[r.driver_name] = { shifts: [], total: 0 };
        byDriver[r.driver_name].shifts.push(r);
        byDriver[r.driver_name].total += r.calculated_pay;
      });
      
      res.json(byDriver);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  return router;
};
