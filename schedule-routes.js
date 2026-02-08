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
      const { name, phone, email, hourly_rate, notes } = req.body;
      if (!name) return res.status(400).json({ error: 'Name required' });
      
      const rate = parseFloat(hourly_rate) || 16.50;
      if (rate < 16.50) {
        return res.status(400).json({ error: 'Hourly rate cannot be below NYC minimum wage ($16.50)' });
      }

      const { rows } = await pool.query(
        `INSERT INTO drivers (name, phone, email, hourly_rate, notes)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [name, phone || null, email || null, rate, notes || null]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add driver error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Update driver
  router.put('/drivers/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, phone, email, hourly_rate, status, notes } = req.body;
      const rate = parseFloat(hourly_rate);
      if (rate && rate < 16.50) {
        return res.status(400).json({ error: 'Hourly rate cannot be below NYC minimum wage ($16.50)' });
      }

      const { rows } = await pool.query(
        `UPDATE drivers SET name=COALESCE($1,name), phone=COALESCE($2,phone),
         email=COALESCE($3,email), hourly_rate=COALESCE($4,hourly_rate),
         status=COALESCE($5,status), notes=COALESCE($6,notes), updated_at=NOW()
         WHERE id=$7 RETURNING *`,
        [name, phone, email, rate || null, status, notes, req.params.id]
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
      const { name, description, active_days, estimated_hours } = req.body;
      if (!name) return res.status(400).json({ error: 'Route name required' });
      const { rows } = await pool.query(
        `INSERT INTO routes (name, description, active_days, estimated_hours)
         VALUES ($1,$2,$3,$4) RETURNING *`,
        [name, description || null, active_days || [1,2,3,4,5,6], estimated_hours || 5.0]
      );
      res.json(rows[0]);
    } catch (err) {
      console.error('Add route error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  router.put('/routes/:id', authenticate, adminOnly, async (req, res) => {
    try {
      const { name, description, active_days, estimated_hours, status } = req.body;
      const { rows } = await pool.query(
        `UPDATE routes SET name=COALESCE($1,name), description=COALESCE($2,description),
         active_days=COALESCE($3,active_days), estimated_hours=COALESCE($4,estimated_hours),
         status=COALESCE($5,status)
         WHERE id=$6 RETURNING *`,
        [name, description, active_days, estimated_hours, status, req.params.id]
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
      const { rows } = await pool.query('SELECT * FROM shift_templates ORDER BY start_time');
      res.json(rows);
    } catch (err) {
      console.error('Get shifts error:', err);
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
        SELECT pr.*, d.name as driver_name, d.hourly_rate
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
        SELECT pr.*, d.name as driver_name, d.hourly_rate
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
      const { pay_period_id } = req.body;
      let period;
      if (pay_period_id) {
        const { rows } = await pool.query('SELECT * FROM pay_periods WHERE id=$1', [pay_period_id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Pay period not found' });
        period = rows[0];
      } else {
        period = await getCurrentPayPeriod();
      }

      // Get approved time entries for this period
      const { rows: entries } = await pool.query(`
        SELECT te.*, d.hourly_rate, d.overtime_rate, d.name as driver_name
        FROM time_entries te
        JOIN drivers d ON te.driver_id = d.id
        WHERE te.work_date BETWEEN $1 AND $2
          AND te.status = 'approved'
        ORDER BY te.driver_id, te.work_date
      `, [period.start_date, period.end_date]);

      // Group by driver
      const byDriver = {};
      entries.forEach(e => {
        if (!byDriver[e.driver_id]) byDriver[e.driver_id] = { entries: [], rate: e.hourly_rate, otRate: e.overtime_rate, name: e.driver_name };
        byDriver[e.driver_id].entries.push(e);
      });

      const results = [];
      for (const [driverId, data] of Object.entries(byDriver)) {
        const totalHours = data.entries.reduce((sum, e) => sum + parseFloat(e.total_hours || 0), 0);

        let effectiveRate = parseFloat(data.rate);
        if (effectiveRate < NYC_MIN_WAGE) effectiveRate = NYC_MIN_WAGE;

        const regularHours = Math.min(totalHours, OT_THRESHOLD);
        const overtimeHours = Math.max(0, totalHours - OT_THRESHOLD);
        const otRate = data.otRate ? parseFloat(data.otRate) : effectiveRate * OT_MULTIPLIER;
        const regularPay = Math.round(regularHours * effectiveRate * 100) / 100;
        const overtimePay = Math.round(overtimeHours * otRate * 100) / 100;
        const grossPay = regularPay + overtimePay;

        // Spread of hours check: if any day > 10 hours, add 1 hour at min wage
        let spreadBonus = 0;
        const dailyHours = {};
        data.entries.forEach(e => {
          const d = typeof e.work_date === 'string' ? e.work_date.split('T')[0] : e.work_date.toISOString().split('T')[0];
          dailyHours[d] = (dailyHours[d] || 0) + parseFloat(e.total_hours || 0);
        });
        Object.values(dailyHours).forEach(h => {
          if (h > 10) spreadBonus += NYC_MIN_WAGE;
        });

        const finalGross = grossPay + spreadBonus;

        await pool.query(`
          INSERT INTO pay_records (pay_period_id, driver_id, regular_hours, overtime_hours,
            regular_pay, overtime_pay, bonuses, gross_pay, status, notes)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'draft',$9)
          ON CONFLICT (pay_period_id, driver_id)
          DO UPDATE SET regular_hours=$3, overtime_hours=$4, regular_pay=$5,
            overtime_pay=$6, bonuses=$7, gross_pay=$8, status='draft',
            notes=$9, updated_at=NOW()
        `, [period.id, parseInt(driverId), regularHours, overtimeHours,
            regularPay, overtimePay, spreadBonus, finalGross,
            spreadBonus > 0 ? `Includes $${spreadBonus.toFixed(2)} spread-of-hours bonus` : null]);

        results.push({
          driver_id: parseInt(driverId),
          driver_name: data.name,
          regular_hours: regularHours,
          overtime_hours: overtimeHours,
          regular_pay: regularPay,
          overtime_pay: overtimePay,
          spread_bonus: spreadBonus,
          gross_pay: finalGross
        });
      }

      // Update period status
      await pool.query("UPDATE pay_periods SET status='calculated' WHERE id=$1", [period.id]);

      res.json({ period, results });
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
        SELECT d.name, d.hourly_rate, pr.regular_hours, pr.overtime_hours,
               pr.regular_pay, pr.overtime_pay, pr.bonuses, pr.gross_pay, pr.notes
        FROM pay_records pr
        JOIN drivers d ON pr.driver_id = d.id
        WHERE pr.pay_period_id = $1
        ORDER BY d.name
      `, [req.params.id]);

      let csv = 'Driver,Hourly Rate,Regular Hours,OT Hours,Regular Pay,OT Pay,Bonuses,Gross Pay,Notes\n';
      rows.forEach(r => {
        csv += `"${r.name}",${r.hourly_rate},${r.regular_hours},${r.overtime_hours},${r.regular_pay},${r.overtime_pay},${r.bonuses},${r.gross_pay},"${r.notes || ''}"\n`;
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
