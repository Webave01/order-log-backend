// schedule-routes.js
// Add to GitHub repo alongside server.js
// Then add these 2 lines to server.js:
//   const scheduleRoutes = require('./schedule-routes');
//   app.use('/api', scheduleRoutes(pool, authenticate, adminOnly));

const express = require('express');

module.exports = function(pool, authenticate, adminOnly) {
  const router = express.Router();

  // =============================================
  // DRIVERS CRUD
  // =============================================
  
  // List all drivers
  router.get('/drivers', authenticate, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM drivers WHERE status != $1 ORDER BY name', ['terminated']
      );
      res.json(rows);
    } catch (err) {
      console.error('Get drivers error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Add driver
  router.post('/drivers', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, phone, email, hourly_rate, day_rate, pay_type, payment_method,
              worker_type, legal_name, dob, address, dl_number, tax_id, tax_id_type,
              zelle_handle, notes } = req.body;
      if (!name) return res.status(400).json({ error: 'Name required' });
      
      const ptype = pay_type === 'flat_day' ? 'flat_day' : 'hourly';
      const rate = parseFloat(hourly_rate) || 16.50;
      if (ptype === 'hourly' && rate < 16.50) {
        return res.status(400).json({ error: 'Hourly rate cannot be below NYC minimum wage ($16.50)' });
      }

      const { rows } = await pool.query(
        `INSERT INTO drivers (name, phone, email, hourly_rate, day_rate, pay_type, payment_method,
         worker_type, legal_name, dob, address, dl_number, tax_id, tax_id_type, zelle_handle, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
        [name, phone||null, email||null, rate, parseFloat(day_rate)||null, ptype,
         payment_method||'cash', worker_type||'1099', legal_name||null, dob||null,
         address||null, dl_number||null, tax_id||null, tax_id_type||'ssn', zelle_handle||null, notes||null]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add driver error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Update driver
  // Driver updates own profile (limited fields - no pay/rate changes)
  router.put('/drivers/my-profile', authenticate, async (req, res) => {
    try {
      // Find driver linked to this user
      const dResult = await pool.query('SELECT id FROM drivers WHERE user_id = $1', [req.user.id]);
      if (dResult.rows.length === 0) return res.status(404).json({ error: 'No driver profile linked to your account' });
      const driverId = dResult.rows[0].id;

      const { phone, payment_method, zelle_handle, legal_name, dob, address, dl_number, tax_id, tax_id_type } = req.body;

      const { rows } = await pool.query(
        `UPDATE drivers SET phone=COALESCE($1,phone), payment_method=COALESCE($2,payment_method),
         zelle_handle=$3, legal_name=$4, dob=$5, address=$6, dl_number=$7,
         tax_id=$8, tax_id_type=COALESCE($9,tax_id_type), updated_at=NOW()
         WHERE id=$10 RETURNING *`,
        [phone||null, payment_method, zelle_handle||null, legal_name||null, dob||null,
         address||null, dl_number||null, tax_id||null, tax_id_type, driverId]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Driver self-update error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Driver gets own profile
  router.get('/drivers/my-profile', authenticate, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM drivers WHERE user_id = $1', [req.user.id]);
      if (rows.length === 0) return res.status(404).json({ error: 'No driver profile linked' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Get my profile error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });
  router.put('/drivers/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, phone, email, hourly_rate, day_rate, pay_type, payment_method,
              worker_type, legal_name, dob, address, dl_number, tax_id, tax_id_type,
              zelle_handle, status, notes } = req.body;
      const rate = parseFloat(hourly_rate);
      if (pay_type !== 'flat_day' && rate && rate < 16.50) {
        return res.status(400).json({ error: 'Hourly rate cannot be below NYC minimum wage ($16.50)' });
      }

      const { rows } = await pool.query(
        `UPDATE drivers SET name=COALESCE($1,name), phone=COALESCE($2,phone),
         email=COALESCE($3,email), hourly_rate=COALESCE($4,hourly_rate),
         day_rate=$5, pay_type=COALESCE($6,pay_type), payment_method=COALESCE($7,payment_method),
         worker_type=COALESCE($8,worker_type), legal_name=$9, dob=$10,
         address=$11, dl_number=$12, tax_id=$13, tax_id_type=COALESCE($14,tax_id_type),
         zelle_handle=$15, status=COALESCE($16,status), notes=COALESCE($17,notes), updated_at=NOW()
         WHERE id=$18 RETURNING *`,
        [name, phone, email, rate||null, parseFloat(day_rate)||null, pay_type,
         payment_method, worker_type, legal_name||null, dob||null,
         address||null, dl_number||null, tax_id||null, tax_id_type,
         zelle_handle||null, status, notes, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Driver not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Update driver error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete (soft) driver
  router.delete('/drivers/:id', authenticate, adminOnly, async (req, res) => {
    try {
      await pool.query("UPDATE drivers SET status='terminated', updated_at=NOW() WHERE id=$1", [req.params.id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Delete driver error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });


  // =============================================
  // ROUTES CRUD
  // =============================================

  router.get('/routes', authenticate, async (req, res) => {
    try {
      const { rows } = await pool.query("SELECT * FROM routes WHERE status='active' ORDER BY name");
      res.json(rows);
    } catch (err) {
      console.error('Get routes error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  router.post('/routes', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, description, active_days, estimated_hours, has_shifts, requires_clock_in } = req.body;
      if (!name) return res.status(400).json({ error: 'Route name required' });
      const { rows } = await pool.query(
        `INSERT INTO routes (name, description, active_days, estimated_hours, has_shifts, requires_clock_in)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [name, description || null, active_days || [1,2,3,4,5,6], estimated_hours || 5.0, has_shifts || false, requires_clock_in || false]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add route error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  router.put('/routes/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, description, active_days, estimated_hours, status, has_shifts, requires_clock_in } = req.body;
      const { rows } = await pool.query(
        `UPDATE routes SET name=COALESCE($1,name), description=COALESCE($2,description),
         active_days=COALESCE($3,active_days), estimated_hours=COALESCE($4,estimated_hours),
         status=COALESCE($5,status), has_shifts=COALESCE($6,has_shifts), requires_clock_in=COALESCE($7,requires_clock_in)
         WHERE id=$8 RETURNING *`,
        [name, description, active_days, estimated_hours, status, has_shifts, requires_clock_in, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Route not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Update route error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // SHIFT TEMPLATES
  // =============================================

  router.get('/shifts', authenticate, async (req, res) => {
    try {
      const { rows } = await pool.query("SELECT * FROM shift_templates ORDER BY CASE name WHEN 'Full Day' THEN 0 WHEN 'AM' THEN 1 WHEN 'PM' THEN 2 ELSE 3 END, start_time");
      res.json(rows);
    } catch (err) {
      console.error('Get shifts error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Add shift
  router.post('/shifts', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, start_time, end_time } = req.body;
      if (!name || !start_time || !end_time) return res.status(400).json({ error: 'name, start_time, end_time required' });
      const { rows } = await pool.query(
        'INSERT INTO shift_templates (name, start_time, end_time) VALUES ($1, $2, $3) RETURNING *',
        [name, start_time, end_time]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add shift error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Update shift
  router.put('/shifts/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, start_time, end_time } = req.body;
      const { rows } = await pool.query(
        'UPDATE shift_templates SET name = COALESCE($1, name), start_time = COALESCE($2, start_time), end_time = COALESCE($3, end_time) WHERE id = $4 RETURNING *',
        [name, start_time, end_time, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Update shift error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete shift
  router.delete('/shifts/:id', authenticate, adminOnly, async (req, res) => {
    try {
      await pool.query('DELETE FROM shift_templates WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Delete shift error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // USER MANAGEMENT
  // =============================================

  const bcrypt = require('bcryptjs');

  // List all users (admin only)
  router.get('/users', authenticate, adminOnly, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT id, username, role, plain_password, created_at FROM users ORDER BY username'
      );
      res.json(rows);
    } catch (err) {
      console.error('Get users error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Create user (admin only)
  router.post('/users', authenticate, adminOnly, async (req, res) => {
    try {
      const { username, password, role, driver_id } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const validRoles = ['admin', 'attendant', 'driver'];
      const userRole = validRoles.includes(role) ? role : 'attendant';
      const hash = await bcrypt.hash(password, 10);
      const { rows } = await pool.query(
        'INSERT INTO users (username, password, role, plain_password) VALUES ($1, $2, $3, $4) RETURNING id, username, role, created_at',
        [username.toLowerCase(), hash, userRole, password]
      );
      // Link to driver profile if driver_id provided
      if (userRole === 'driver' && driver_id) {
        await pool.query('UPDATE drivers SET user_id = $1 WHERE id = $2', [rows[0].id, driver_id]);
      }
      res.json(rows[0]);
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Create user error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Update user (admin only)
  router.put('/users/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { username, password, role, driver_id } = req.body;
      const validRoles = ['admin', 'attendant', 'driver'];
      const userId = req.params.id;
      if (password) {
        const hash = await bcrypt.hash(password, 10);
        const { rows } = await pool.query(
          'UPDATE users SET username = COALESCE($1, username), password = $2, role = COALESCE($3, role), plain_password = $4 WHERE id = $5 RETURNING id, username, role, created_at',
          [username ? username.toLowerCase() : undefined, hash, validRoles.includes(role) ? role : undefined, password, userId]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
        // Update driver linking
        if (role === 'driver' && driver_id) {
          await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
          await pool.query('UPDATE drivers SET user_id = $1 WHERE id = $2', [userId, driver_id]);
        } else if (role !== 'driver') {
          await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
        }
        res.json(rows[0]);
      } else {
        const { rows } = await pool.query(
          'UPDATE users SET username = COALESCE($1, username), role = COALESCE($2, role) WHERE id = $3 RETURNING id, username, role, created_at',
          [username ? username.toLowerCase() : undefined, validRoles.includes(role) ? role : undefined, userId]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
        // Update driver linking
        if (role === 'driver' && driver_id) {
          await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
          await pool.query('UPDATE drivers SET user_id = $1 WHERE id = $2', [userId, driver_id]);
        } else if (role !== 'driver') {
          await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [userId]);
        }
        res.json(rows[0]);
      }
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Update user error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete user (admin only)
  router.delete('/users/:id', authenticate, adminOnly, async (req, res) => {
    try {
      // Prevent deleting yourself
      if (parseInt(req.params.id) === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
      }
      // Unlink any driver profiles
      await pool.query('UPDATE drivers SET user_id = NULL WHERE user_id = $1', [req.params.id]);
      await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Delete user error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // DRIVER AVAILABILITY
  // =============================================

  // Get availability for a date range (admin sees all, driver sees own)
  router.get('/availability', authenticate, async (req, res) => {
    try {
      const { start_date, end_date, driver_id } = req.query;
      let query = `SELECT da.*, d.name as driver_name, r.name as route_name 
        FROM driver_availability da 
        JOIN drivers d ON da.driver_id = d.id 
        LEFT JOIN routes r ON da.preferred_route_id = r.id 
        WHERE 1=1`;
      const params = [];

      if (start_date) { params.push(start_date); query += ` AND da.work_date >= $${params.length}`; }
      if (end_date) { params.push(end_date); query += ` AND da.work_date <= $${params.length}`; }
      if (driver_id) { params.push(parseInt(driver_id)); query += ` AND da.driver_id = $${params.length}`; }

      // Non-admin only sees own
      if (req.user.role === 'driver') {
        const dResult = await pool.query('SELECT id FROM drivers WHERE user_id = $1', [req.user.id]);
        if (dResult.rows.length > 0) {
          params.push(dResult.rows[0].id);
          query += ` AND da.driver_id = $${params.length}`;
        } else {
          return res.json([]);
        }
      }

      query += ' ORDER BY da.work_date, d.name';
      const { rows } = await pool.query(query, params);
      
      // Enrich route_selections with route names
      const routeCache = {};
      const allRoutes = await pool.query("SELECT id, name, has_shifts, requires_clock_in FROM routes WHERE status='active'");
      allRoutes.rows.forEach(r => { routeCache[r.id] = r; });
      
      const enriched = rows.map(row => {
        let selections = row.route_selections || [];
        if (typeof selections === 'string') try { selections = JSON.parse(selections); } catch(e) { selections = []; }
        // Backfill from preferred_route_id if route_selections empty
        if ((!selections || selections.length === 0) && row.preferred_route_id) {
          selections = [{ route_id: row.preferred_route_id, shift: row.preferred_shift }];
        }
        selections = selections.map(s => ({
          ...s,
          route_name: routeCache[s.route_id] ? routeCache[s.route_id].name : null,
          has_shifts: routeCache[s.route_id] ? routeCache[s.route_id].has_shifts : false
        }));
        return { ...row, route_selections: selections };
      });
      
      res.json(enriched);
    } catch (err) {
      console.error('Get availability error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Driver submits availability with multi-route support
  router.post('/availability', authenticate, async (req, res) => {
    try {
      const { driver_id, work_date, status, route_selections, preferred_route_id, preferred_shift, notes, confirmed, admin_confirmed } = req.body;
      if (!driver_id || !work_date) return res.status(400).json({ error: 'driver_id and work_date required' });

      // Verify driver owns this profile (unless admin)
      if (req.user.role !== 'admin') {
        const dResult = await pool.query('SELECT id FROM drivers WHERE user_id = $1 AND id = $2', [req.user.id, driver_id]);
        if (dResult.rows.length === 0) return res.status(403).json({ error: 'Not authorized' });
      }

      // Build route_selections - accept new format or legacy single route
      let selections = route_selections || [];
      if (selections.length === 0 && preferred_route_id) {
        selections = [{ route_id: preferred_route_id, shift: preferred_shift || null }];
      }
      
      // Conflict check: East + West cannot be selected together
      if (selections.length > 1) {
        const routeIds = selections.map(s => parseInt(s.route_id));
        const { rows: routeNames } = await pool.query('SELECT id, name FROM routes WHERE id = ANY($1)', [routeIds]);
        const names = routeNames.map(r => r.name.toLowerCase());
        if (names.some(n => n.includes('east')) && names.some(n => n.includes('west'))) {
          return res.status(400).json({ error: 'East and West routes cannot be selected together - time conflict' });
        }
      }

      // Store first route as preferred_route_id for backward compat
      const primaryRouteId = selections.length > 0 ? parseInt(selections[0].route_id) : null;
      const primaryShift = selections.length > 0 ? selections[0].shift : null;

      const isAdmin = req.user.role === 'admin';
      const { rows } = await pool.query(
        `INSERT INTO driver_availability (driver_id, work_date, status, preferred_route_id, preferred_shift, route_selections, notes, confirmed, admin_confirmed)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
         ON CONFLICT (driver_id, work_date)
         DO UPDATE SET status = $3, preferred_route_id = $4, preferred_shift = $5, route_selections = $6::jsonb, notes = $7, confirmed = $8,
           admin_confirmed = CASE WHEN $10 THEN $9 ELSE driver_availability.admin_confirmed END,
           updated_at = NOW()
         RETURNING *`,
        [driver_id, work_date, status || 'available', primaryRouteId, primaryShift, JSON.stringify(selections), notes || null, confirmed || false, admin_confirmed || false, isAdmin]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Set availability error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete availability entry (48-hour rule for drivers)
  router.delete('/availability/:id', authenticate, async (req, res) => {
    try {
      const isAdmin = req.user.role === 'admin';

      if (!isAdmin) {
        // Verify ownership
        const check = await pool.query(
          'SELECT da.id, da.work_date, da.admin_confirmed FROM driver_availability da JOIN drivers d ON da.driver_id = d.id WHERE da.id = $1 AND d.user_id = $2',
          [req.params.id, req.user.id]
        );
        if (check.rows.length === 0) return res.status(403).json({ error: 'Not authorized' });

        // Admin-confirmed schedules cannot be cancelled by driver
        if (check.rows[0].admin_confirmed) {
          return res.status(403).json({ error: 'This schedule has been confirmed by admin and cannot be changed. Contact your manager.' });
        }

        // 48-hour rule
        const workDate = new Date(check.rows[0].work_date);
        const now = new Date();
        const hoursUntil = (workDate.getTime() - now.getTime()) / (1000 * 60 * 60);
        if (hoursUntil < 48) {
          return res.status(403).json({ error: 'Cannot cancel within 48 hours of the scheduled date. Contact your manager.' });
        }
      }

      await pool.query('DELETE FROM driver_availability WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Delete availability error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Admin: confirm schedule as final
  router.put('/availability/:id/confirm', authenticate, adminOnly, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'UPDATE driver_availability SET admin_confirmed = true, updated_at = NOW() WHERE id = $1 RETURNING *',
        [req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Confirm availability error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Admin: bulk confirm all availability for a week
  router.put('/availability/confirm-week', authenticate, adminOnly, async (req, res) => {
    try {
      const { start_date, end_date } = req.body;
      const { rows } = await pool.query(
        `UPDATE driver_availability SET admin_confirmed = true, updated_at = NOW()
         WHERE work_date BETWEEN $1 AND $2 AND confirmed = true AND admin_confirmed = false
         RETURNING *`,
        [start_date, end_date]
      );
      res.json({ confirmed: rows.length });
    } catch (err) {
      console.error('Bulk confirm error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Admin: get coverage summary for a week (who's available, what's unfilled)
  router.get('/availability/coverage', authenticate, adminOnly, async (req, res) => {
    try {
      const { week_of } = req.query;
      if (!week_of) return res.status(400).json({ error: 'week_of required' });

      // Get all confirmed availability for the week
      const endDate = new Date(week_of);
      endDate.setDate(endDate.getDate() + 5);
      const endStr = endDate.toISOString().split('T')[0];

      const { rows: available } = await pool.query(
        `SELECT da.*, d.name as driver_name
         FROM driver_availability da JOIN drivers d ON da.driver_id = d.id
         WHERE da.work_date BETWEEN $1 AND $2 AND da.confirmed = true AND da.status = 'available'
         ORDER BY da.work_date, d.name`,
        [week_of, endStr]
      );

      // Get assignments for the same week
      const { rows: assignments } = await pool.query(
        `SELECT sa.*, d.name as driver_name
         FROM schedule_assignments sa LEFT JOIN drivers d ON sa.driver_id = d.id
         WHERE sa.start_date = $1`,
        [week_of]
      );

      res.json({ available, assignments });
    } catch (err) {
      console.error('Get coverage error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // SCHEDULE ASSIGNMENTS
  // =============================================

  // Get schedule for a specific week
  router.get('/schedule', authenticate, async (req, res) => {
    try {
      // Default to current week
      const dateParam = req.query.week_of;
      let weekStart;
      if (dateParam) {
        weekStart = new Date(dateParam);
      } else {
        weekStart = new Date();
      }
      // Adjust to Monday of that week
      const day = weekStart.getDay();
      const diff = day === 0 ? -6 : 1 - day;
      weekStart.setDate(weekStart.getDate() + diff);
      weekStart.setHours(0,0,0,0);

      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekEnd.getDate() + 6);

      // Get recurring assignments that are active for this week
      const { rows: assignments } = await pool.query(`
        SELECT sa.*, d.name as driver_name, d.phone as driver_phone,
               r.name as route_name, r.active_days,
               st.name as shift_name, st.start_time, st.end_time
        FROM schedule_assignments sa
        JOIN drivers d ON sa.driver_id = d.id
        JOIN routes r ON sa.route_id = r.id
        JOIN shift_templates st ON sa.shift_template_id = st.id
        WHERE sa.effective_date <= $1
          AND (sa.end_date IS NULL OR sa.end_date >= $2)
          AND d.status = 'active'
        ORDER BY sa.day_of_week, st.start_time, r.name
      `, [weekEnd.toISOString().split('T')[0], weekStart.toISOString().split('T')[0]]);

      // Get exceptions for this week
      const { rows: exceptions } = await pool.query(`
        SELECT se.*, d.name as replacement_driver_name
        FROM schedule_exceptions se
        LEFT JOIN drivers d ON se.replacement_driver_id = d.id
        WHERE se.exception_date BETWEEN $1 AND $2
      `, [weekStart.toISOString().split('T')[0], weekEnd.toISOString().split('T')[0]]);

      // Get time entries for this week
      const { rows: timeEntries } = await pool.query(`
        SELECT * FROM time_entries
        WHERE work_date BETWEEN $1 AND $2
        ORDER BY work_date, clock_in
      `, [weekStart.toISOString().split('T')[0], weekEnd.toISOString().split('T')[0]]);

      res.json({
        week_start: weekStart.toISOString().split('T')[0],
        week_end: weekEnd.toISOString().split('T')[0],
        assignments,
        exceptions,
        timeEntries
      });
    } catch (err) {
      console.error('Get schedule error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Create assignment
  router.post('/schedule/assign', authenticate, adminOnly, async (req, res) => {
    try {
      const { driver_id, route_id, shift_template_id, day_of_week, effective_date } = req.body;
      if (!driver_id || !route_id || !shift_template_id || day_of_week === undefined) {
        return res.status(400).json({ error: 'driver_id, route_id, shift_template_id, and day_of_week required' });
      }

      // Check route is active on this day
      const { rows: routeCheck } = await pool.query(
        'SELECT active_days FROM routes WHERE id=$1', [route_id]
      );
      if (routeCheck.length === 0) return res.status(404).json({ error: 'Route not found' });
      if (!routeCheck[0].active_days.includes(day_of_week)) {
        return res.status(400).json({ error: 'Route is not active on this day' });
      }

      const { rows } = await pool.query(
        `INSERT INTO schedule_assignments (driver_id, route_id, shift_template_id, day_of_week, effective_date)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [driver_id, route_id, shift_template_id, day_of_week, effective_date || new Date().toISOString().split('T')[0]]
      );
      res.json(rows[0]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(400).json({ error: 'This route/shift/day is already assigned' });
      }
      console.error('Assign schedule error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Update assignment
  router.put('/schedule/assign/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { driver_id, end_date } = req.body;
      const { rows } = await pool.query(
        `UPDATE schedule_assignments SET driver_id=COALESCE($1,driver_id),
         end_date=COALESCE($2,end_date), updated_at=NOW()
         WHERE id=$3 RETURNING *`,
        [driver_id, end_date, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Update assignment error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Delete assignment
  router.delete('/schedule/assign/:id', authenticate, adminOnly, async (req, res) => {
    try {
      await pool.query('DELETE FROM schedule_assignments WHERE id=$1', [req.params.id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Delete assignment error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // SCHEDULE EXCEPTIONS
  // =============================================

  router.post('/schedule/exception', authenticate, async (req, res) => {
    try {
      const { original_assignment_id, exception_date, exception_type, replacement_driver_id, reason } = req.body;
      if (!exception_date || !exception_type) {
        return res.status(400).json({ error: 'exception_date and exception_type required' });
      }

      const { rows } = await pool.query(
        `INSERT INTO schedule_exceptions
         (original_assignment_id, exception_date, exception_type, replacement_driver_id, reason)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [original_assignment_id, exception_date, exception_type, replacement_driver_id || null, reason || null]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add exception error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  router.put('/schedule/exception/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { status } = req.body;
      const { rows } = await pool.query(
        `UPDATE schedule_exceptions SET status=$1, approved_by=$2, approved_at=NOW()
         WHERE id=$3 RETURNING *`,
        [status, req.user.id, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Exception not found' });
      res.json(rows[0]);
    } catch (err) {
      console.error('Update exception error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // TIME TRACKING
  // =============================================

  // Clock in
  router.post('/time/clock-in', authenticate, async (req, res) => {
    try {
      const { driver_id, route_id, shift_template_id } = req.body;
      if (!driver_id || !route_id) {
        return res.status(400).json({ error: 'driver_id and route_id required' });
      }

      const now = new Date();
      const workDate = now.toISOString().split('T')[0];

      // Check for existing open entry today
      const { rows: existing } = await pool.query(
        `SELECT * FROM time_entries WHERE driver_id=$1 AND work_date=$2 AND clock_out IS NULL`,
        [driver_id, workDate]
      );
      if (existing.length > 0) {
        return res.status(400).json({ error: 'Driver already clocked in. Clock out first.' });
      }

      const { rows } = await pool.query(
        `INSERT INTO time_entries (driver_id, route_id, shift_template_id, work_date, clock_in)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [driver_id, route_id, shift_template_id || null, workDate, now.toISOString()]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Clock in error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Clock out
  router.post('/time/clock-out', authenticate, async (req, res) => {
    try {
      const { driver_id } = req.body;
      if (!driver_id) return res.status(400).json({ error: 'driver_id required' });

      const now = new Date();
      const workDate = now.toISOString().split('T')[0];

      // Find open entry
      const { rows: open } = await pool.query(
        `SELECT * FROM time_entries WHERE driver_id=$1 AND work_date=$2 AND clock_out IS NULL`,
        [driver_id, workDate]
      );
      if (open.length === 0) {
        return res.status(400).json({ error: 'No open clock-in found for today' });
      }

      const entry = open[0];
      const clockIn = new Date(entry.clock_in);
      const totalHours = ((now - clockIn) / (1000 * 60 * 60)) - (entry.break_minutes / 60);

      const { rows } = await pool.query(
        `UPDATE time_entries SET clock_out=$1, total_hours=$2, updated_at=NOW()
         WHERE id=$3 RETURNING *`,
        [now.toISOString(), Math.round(totalHours * 100) / 100, entry.id]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Clock out error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Get time entries for a date range
  router.get('/time/entries', authenticate, async (req, res) => {
    try {
      const { start_date, end_date, driver_id } = req.query;
      let query = `
        SELECT te.*, d.name as driver_name, r.name as route_name, st.name as shift_name
        FROM time_entries te
        JOIN drivers d ON te.driver_id = d.id
        JOIN routes r ON te.route_id = r.id
        LEFT JOIN shift_templates st ON te.shift_template_id = st.id
        WHERE 1=1
      `;
      const params = [];
      if (start_date) { params.push(start_date); query += ` AND te.work_date >= $${params.length}`; }
      if (end_date) { params.push(end_date); query += ` AND te.work_date <= $${params.length}`; }
      if (driver_id) { params.push(driver_id); query += ` AND te.driver_id = $${params.length}`; }
      query += ' ORDER BY te.work_date DESC, te.clock_in DESC';

      const { rows } = await pool.query(query, params);
      res.json(rows);
    } catch (err) {
      console.error('Get time entries error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Manual time entry (admin)
  router.post('/time/manual', authenticate, adminOnly, async (req, res) => {
    try {
      const { driver_id, route_id, shift_template_id, work_date, clock_in, clock_out, break_minutes, notes } = req.body;
      if (!driver_id || !route_id || !work_date || !clock_in || !clock_out) {
        return res.status(400).json({ error: 'driver_id, route_id, work_date, clock_in, clock_out required' });
      }

      const inTime = new Date(clock_in);
      const outTime = new Date(clock_out);
      const totalHours = ((outTime - inTime) / (1000 * 60 * 60)) - ((break_minutes || 0) / 60);

      const { rows } = await pool.query(
        `INSERT INTO time_entries (driver_id, route_id, shift_template_id, work_date, clock_in, clock_out, break_minutes, total_hours, status, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'approved',$9) RETURNING *`,
        [driver_id, route_id, shift_template_id || null, work_date, clock_in, clock_out, break_minutes || 0, Math.round(totalHours * 100) / 100, notes || null]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Manual time entry error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Approve time entries
  router.post('/time/approve', authenticate, adminOnly, async (req, res) => {
    try {
      const { entry_ids } = req.body;
      if (!entry_ids || !entry_ids.length) return res.status(400).json({ error: 'entry_ids required' });

      await pool.query(
        `UPDATE time_entries SET status='approved', approved_by=$1, approved_at=NOW(), updated_at=NOW()
         WHERE id = ANY($2)`,
        [req.user.id, entry_ids]
      );
      res.json({ success: true, approved: entry_ids.length });
    } catch (err) {
      console.error('Approve time entries error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // =============================================
  // PAY CALCULATION
  // =============================================

  const NYC_MIN_WAGE = 16.50;
  const OT_THRESHOLD = 40;
  const OT_MULTIPLIER = 1.5;

  // Get or create current pay period (Sun-Sat)
  async function getCurrentPayPeriod() {
    const now = new Date();
    const day = now.getDay(); // 0=Sun
    const startDate = new Date(now);
    startDate.setDate(startDate.getDate() - day); // Sunday
    startDate.setHours(0,0,0,0);
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + 6); // Saturday

    const startStr = startDate.toISOString().split('T')[0];
    const endStr = endDate.toISOString().split('T')[0];

    // Check if exists
    const { rows } = await pool.query(
      'SELECT * FROM pay_periods WHERE start_date=$1 AND end_date=$2', [startStr, endStr]
    );
    if (rows.length > 0) return rows[0];

    // Create
    const { rows: created } = await pool.query(
      'INSERT INTO pay_periods (start_date, end_date) VALUES ($1,$2) RETURNING *',
      [startStr, endStr]
    );
    return created[0];
  }

  // Get current pay period summary
  router.get('/pay/current', authenticate, async (req, res) => {
    try {
      const period = await getCurrentPayPeriod();
      const { rows: records } = await pool.query(`
        SELECT pr.*, d.name as driver_name, d.hourly_rate, d.pay_type, d.day_rate, d.payment_method
        FROM pay_records pr
        JOIN drivers d ON pr.driver_id = d.id
        WHERE pr.pay_period_id = $1
        ORDER BY d.name
      `, [period.id]);

      res.json({ period, records });
    } catch (err) {
      console.error('Get current pay error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Get specific pay period
  router.get('/pay/period/:id', authenticate, async (req, res) => {
    try {
      const { rows: periods } = await pool.query('SELECT * FROM pay_periods WHERE id=$1', [req.params.id]);
      if (periods.length === 0) return res.status(404).json({ error: 'Pay period not found' });

      const { rows: records } = await pool.query(`
        SELECT pr.*, d.name as driver_name, d.hourly_rate, d.pay_type, d.day_rate, d.payment_method
        FROM pay_records pr
        JOIN drivers d ON pr.driver_id = d.id
        WHERE pr.pay_period_id = $1
        ORDER BY d.name
      `, [req.params.id]);

      res.json({ period: periods[0], records });
    } catch (err) {
      console.error('Get pay period error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // List all pay periods
  router.get('/pay/periods', authenticate, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM pay_periods ORDER BY start_date DESC LIMIT 20');
      res.json(rows);
    } catch (err) {
      console.error('Get pay periods error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Calculate pay for a period
  router.post('/pay/calculate', authenticate, adminOnly, async (req, res) => {
    try {
      const { period_id, pay_period_id } = req.body;
      const pid = period_id || pay_period_id;
      let period;
      if (pid) {
        const { rows } = await pool.query('SELECT * FROM pay_periods WHERE id=$1', [pid]);
        if (rows.length === 0) return res.status(404).json({ error: 'Pay period not found' });
        period = rows[0];
      } else {
        period = await getCurrentPayPeriod();
      }

      // Get admin-confirmed schedule entries for this period with route info
      const { rows: confirmed } = await pool.query(`
        SELECT da.driver_id, da.work_date, da.preferred_shift, da.preferred_route_id,
               d.name as driver_name, d.day_rate, d.pay_type, d.payment_method,
               r.name as route_name, r.requires_clock_in, r.has_shifts
        FROM driver_availability da
        JOIN drivers d ON da.driver_id = d.id
        LEFT JOIN routes r ON da.preferred_route_id = r.id
        WHERE da.work_date BETWEEN $1 AND $2
          AND da.confirmed = true
          AND da.admin_confirmed = true
        ORDER BY da.driver_id, da.work_date
      `, [period.start_date, period.end_date]);

      // Group by driver
      const byDriver = {};
      confirmed.forEach(row => {
        if (!byDriver[row.driver_id]) {
          byDriver[row.driver_id] = {
            entries: [], name: row.driver_name,
            pay_type: row.pay_type, day_rate: row.day_rate,
            payment_method: row.payment_method
          };
        }
        byDriver[row.driver_id].entries.push(row);
      });

      let processed = 0;
      const results = [];

      for (const [driverId, data] of Object.entries(byDriver)) {
        // Categorize entries by route type
        let fullDays = 0, amShifts = 0, pmShifts = 0;
        const routeSummary = {};
        const clockInDays = [];

        data.entries.forEach(e => {
          const routeName = e.route_name || 'Unknown';
          if (!routeSummary[routeName]) routeSummary[routeName] = { full: 0, am: 0, pm: 0, clockIn: 0 };

          if (e.requires_clock_in) {
            routeSummary[routeName].clockIn++;
            clockInDays.push({ date: e.work_date, route: routeName });
          } else if (e.preferred_shift === 'AM') {
            amShifts++;
            routeSummary[routeName].am++;
          } else if (e.preferred_shift === 'PM') {
            pmShifts++;
            routeSummary[routeName].pm++;
          } else {
            fullDays++;
            routeSummary[routeName].full++;
          }
        });

        // Calculate pay for full days only (flat day rate)
        const dayRate = parseFloat(data.day_rate) || 0;
        const fullDayPay = Math.round(fullDays * dayRate * 100) / 100;

        // Build summary notes
        const noteParts = [];
        if (fullDays > 0) noteParts.push(fullDays + ' full day' + (fullDays !== 1 ? 's' : '') + ' @ $' + dayRate.toFixed(2));
        if (amShifts > 0) noteParts.push(amShifts + ' AM shift' + (amShifts !== 1 ? 's' : '') + ' (set pay manually)');
        if (pmShifts > 0) noteParts.push(pmShifts + ' PM shift' + (pmShifts !== 1 ? 's' : '') + ' (set pay manually)');
        if (clockInDays.length > 0) noteParts.push(clockInDays.length + ' clock-in route day' + (clockInDays.length !== 1 ? 's' : '') + ' (needs hours)');

        // Build route breakdown
        const routeBreakdown = Object.entries(routeSummary).map(([name, counts]) => {
          const parts = [];
          if (counts.full > 0) parts.push(counts.full + ' full');
          if (counts.am > 0) parts.push(counts.am + ' AM');
          if (counts.pm > 0) parts.push(counts.pm + ' PM');
          if (counts.clockIn > 0) parts.push(counts.clockIn + ' clock-in');
          return name + ': ' + parts.join(', ');
        }).join(' | ');

        const payNotes = noteParts.join(' | ') + '\n' + routeBreakdown;

        await pool.query(`
          INSERT INTO pay_records (pay_period_id, driver_id, regular_hours, overtime_hours,
            regular_pay, overtime_pay, bonuses, gross_pay, status, notes)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'draft',$9)
          ON CONFLICT (pay_period_id, driver_id)
          DO UPDATE SET regular_hours=$3, overtime_hours=$4, regular_pay=$5,
            overtime_pay=$6, bonuses=$7, gross_pay=$8, status='draft',
            notes=$9, updated_at=NOW()
        `, [period.id, parseInt(driverId),
            fullDays, amShifts + pmShifts,
            fullDayPay, 0, 0, fullDayPay,
            payNotes]);

        results.push({
          driver_id: parseInt(driverId), driver_name: data.name,
          full_days: fullDays, am_shifts: amShifts, pm_shifts: pmShifts,
          clock_in_days: clockInDays.length, full_day_pay: fullDayPay,
          route_summary: routeSummary, payment_method: data.payment_method,
          notes: payNotes
        });
        processed++;
      }

      await pool.query("UPDATE pay_periods SET status='calculated' WHERE id=$1", [period.id]);
      res.json({ period, results, processed });
    } catch (err) {
      console.error('Calculate pay error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Approve pay period
  router.post('/pay/approve', authenticate, adminOnly, async (req, res) => {
    try {
      const { pay_period_id } = req.body;
      await pool.query("UPDATE pay_records SET status='approved', updated_at=NOW() WHERE pay_period_id=$1", [pay_period_id]);
      await pool.query("UPDATE pay_periods SET status='approved' WHERE id=$1", [pay_period_id]);
      res.json({ success: true });
    } catch (err) {
      console.error('Approve pay error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Export pay period as CSV (accepts token via query param for browser download)
  router.get('/pay/export/:id', (req, res, next) => {
    if (req.query.token && !req.headers.authorization) {
      req.headers.authorization = `Bearer ${req.query.token}`;
    }
    next();
  }, authenticate, adminOnly, async (req, res) => {
    try {
      const { rows: period } = await pool.query('SELECT * FROM pay_periods WHERE id=$1', [req.params.id]);
      if (period.length === 0) return res.status(404).json({ error: 'Pay period not found' });

      const { rows } = await pool.query(`
        SELECT d.name, d.hourly_rate, d.pay_type, d.day_rate, d.payment_method, pr.regular_hours, pr.overtime_hours,
               pr.regular_pay, pr.overtime_pay, pr.bonuses, pr.gross_pay, pr.notes
        FROM pay_records pr
        JOIN drivers d ON pr.driver_id = d.id
        WHERE pr.pay_period_id = $1
        ORDER BY d.name
      `, [req.params.id]);

      let csv = 'Driver,Pay Type,Rate,Payment Method,Regular Hours,OT Hours,Regular Pay,OT Pay,Bonuses,Gross Pay,Notes\n';
      rows.forEach(r => {
        const rateStr = r.pay_type === 'flat_day' ? (r.day_rate + '/day') : (r.hourly_rate + '/hr');
        csv += `"${r.name}",${r.pay_type || 'hourly'},${rateStr},${r.payment_method || 'cash'},${r.regular_hours},${r.overtime_hours},${r.regular_pay},${r.overtime_pay},${r.bonuses},${r.gross_pay},"${r.notes || ''}"\n`;
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=payroll-${period[0].start_date}-to-${period[0].end_date}.csv`);
      res.send(csv);
    } catch (err) {
      console.error('Export pay error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  return router;
};