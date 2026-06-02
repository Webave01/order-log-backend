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
      await pool.query("UPDATE drivers SET status = 'terminated' WHERE id = $1", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
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
        [name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days || '', category || 'regular', sort_order || 99, notes, day_of_week]
      );
      res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  router.put('/shifts/:id', authenticate, adminOnly, async (req, res) => {
    const { name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days, category, sort_order, notes, day_of_week } = req.body;
    try {
      const result = await pool.query(
        `UPDATE shifts SET name=$1, start_time=$2, end_time=$3, hours=$4, base_pay=$5, heavy_pay=$6, heavy_days=$7, category=$8, sort_order=$9, notes=$10, day_of_week=$11 WHERE id=$12 RETURNING *`,
        [name, start_time, end_time, hours, base_pay, heavy_pay, heavy_days || '', category, sort_order, notes, day_of_week, req.params.id]
      );
      res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
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
        const result = await pool.query(
          'UPDATE shift_assignments SET driver_id=$1, pay_override=$2, notes=$3, status=$4 WHERE shift_id=$5 AND work_date=$6 RETURNING *',
          [driver_id, pay_override || null, notes, 'assigned', shift_id, work_date]
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
          
          // Check if already exists
          const exists = await pool.query('SELECT id FROM shift_assignments WHERE shift_id = $1 AND work_date = $2', [shift.id, dateStr]);
          if (exists.rows.length === 0) {
            await pool.query('INSERT INTO shift_assignments (shift_id, work_date, status) VALUES ($1, $2, $3)', [shift.id, dateStr, 'open']);
            created++;
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
        ORDER BY sr.created_at DESC LIMIT 50
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
      await pool.query('UPDATE shift_requests SET status = $1 WHERE id = $2', [status, req.params.id]);
      
      // If approved, assign the driver
      if (status === 'approved') {
        // Find driver by name
        const driver = await pool.query("SELECT id FROM drivers WHERE LOWER(name) = LOWER($1) AND status = 'active' LIMIT 1", [sr.driver_name]);
        if (driver.rows.length > 0) {
          await pool.query(
            'INSERT INTO shift_assignments (shift_id, driver_id, work_date, status) VALUES ($1,$2,$3,$4) ON CONFLICT (shift_id, work_date) DO UPDATE SET driver_id=$2, status=$4',
            [sr.shift_id, driver.rows[0].id, sr.work_date, 'assigned']
          );
        }
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
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
