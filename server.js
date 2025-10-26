const express = require('express');
const mysql = require('mysql2/promise'); // Use promise-based version
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_needs_to_be_long'; // IMPORTANT: Use a complex secret in .env

// ----------------------------------------------------------------------
// 1. DATABASE CONNECTION POOL
// ----------------------------------------------------------------------

const pool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware
app.use(cors());
app.use(express.json());

// ----------------------------------------------------------------------
// 2. AUTHENTICATION MIDDLEWARE
// ----------------------------------------------------------------------

const checkAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header missing.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token missing.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

const checkAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ error: 'Access denied: Admin role required.' });
    }
};

// ----------------------------------------------------------------------
// 3. HELPER FUNCTIONS (The Algorithm Components)
// ----------------------------------------------------------------------

// Function to safely parse coordinates "lat,lng"
function parseCoords(coords) {
    if (!coords) return null;
    const parts = coords.split(',').map(p => parseFloat(p.trim()));
    if (parts.length === 2 && !isNaN(parts[0]) && !isNaN(parts[1])) {
        return { lat: parts[0], lng: parts[1] };
    }
    return null;
}

// Simple Euclidean Distance for quick comparison (assumes coordinates are close)
function getEuclideanDistance(coord1, coord2) {
    const c1 = parseCoords(coord1);
    const c2 = parseCoords(coord2);
    if (!c1 || !c2) return Infinity;

    // We use the difference in coordinates squared for simplicity (faster than Haversine)
    return Math.sqrt(Math.pow(c1.lat - c2.lat, 2) + Math.pow(c1.lng - c2.lng, 2));
}

// ----------------------------------------------------------------------
// 4. AUTH ROUTES (Login/Register)
// ----------------------------------------------------------------------

// POST /api/auth/register: Register a new user
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    // Simple role assignment for demo: 'admin' if username is 'admin', otherwise 'user'
    const role = username === 'admin' ? 'admin' : 'user';

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO User (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, role]
        );
        
        // Auto-login after registration
        const token = jwt.sign({ id: result.insertId, username, role }, JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ message: 'User registered successfully', token, username, role });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Username already taken.' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to register user.' });
    }
});

// POST /api/auth/login: Log in an existing user
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const [rows] = await pool.execute('SELECT * FROM User WHERE username = ?', [username]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username, role: user.role });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});


// ----------------------------------------------------------------------
// 5. PROTECTED DATA ROUTES
// ----------------------------------------------------------------------

// GET /api/reports: Comprehensive report (Protected by checkAuth)
app.get('/api/reports', checkAuth, async (req, res) => {
    
    // --- THIS IS THE CORRECTED QUERY ---
    // It now correctly uses LEFT JOINs for all optional data (Operator, Supervisor, Depot)
    // to prevent the query from failing if a record is missing a linked operator.
    const query = `
        SELECT
            dt.TaskID, dt.Status AS TaskStatus, dt.EstimatedQuantity, dt.LocationCoords, dt.CreatedAt,
            dt.AssignedDepotID,
            z.ZoneID, z.ZoneName,
            s.SiteID, s.SiteName,
            d.DroneID, d.Model AS DroneModel,
            o.Name AS OperatorName,
            sup.Name AS SupervisorName,
            td.DepotName AS AssignedDepotName,
            dr.DetectionTime,
            dt.SiteID
        FROM DebrisTask dt
        JOIN Zone z ON dt.ZoneID = z.ZoneID
        JOIN CollectionSite s ON dt.SiteID = s.SiteID
        JOIN DroneTask dr ON dt.TaskID = dr.TaskID
        JOIN Drone d ON dr.DroneID = d.DroneID
        LEFT JOIN TaskOperator topt ON dt.TaskID = topt.TaskID
        LEFT JOIN Operator o ON topt.EmpID = o.EmpID
        LEFT JOIN Supervisor sup ON z.SupervisorID = sup.SupervisorID
        LEFT JOIN TruckDepot td ON dt.AssignedDepotID = td.DepotID 
        ORDER BY dt.TaskID DESC;
    `;
    // --- END OF CORRECTED QUERY ---

    try {
        console.log("Attempting to fetch reports with corrected query...");
        const [results] = await pool.execute(query);
        console.log(`Successfully fetched ${results.length} reports.`);
        res.json(results);
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ error: 'Failed to retrieve report data.' });
    }
});

// GET /api/drones: Drone status list (Protected by checkAuth)
app.get('/api/drones', checkAuth, async (req, res) => {
    
    // --- THIS IS THE FIXED, COMPLETE CODE FOR THIS ROUTE ---
    const sql = `SELECT DroneID, Model, BatteryLife, AssignedZoneID FROM Drone`;
    try {
        console.log("Attempting to fetch drones...");
        const [results] = await pool.execute(sql);
        console.log(`Successfully fetched ${results.length} drones.`);
        res.json(results);
    } catch (error) {
        console.error('Error fetching drones:', error);
        res.status(500).json({ error: 'Failed to retrieve drone data.' });
    }
    // --- END OF FIXED CODE ---
});

// POST /api/reports: Simulate a new drone report (Protected by checkAuth & checkAdmin)
app.post('/api/reports', checkAuth, checkAdmin, async (req, res) => {
    
    // --- THIS IS THE FIXED, COMPLETE CODE FOR THIS ROUTE ---
    const { SiteID, DroneID, EstimatedQuantity, LocationCoords } = req.body;
    
    try {
        console.log("Attempting to create new report...");
        // 1. Validate SiteID
        const [siteCheck] = await pool.execute('SELECT ZoneID FROM CollectionSite WHERE SiteID = ?', [SiteID]);
        if (siteCheck.length === 0) {
            console.log(`Report creation failed: SiteID ${SiteID} does not exist.`);
            return res.status(400).json({ error: `SiteID ${SiteID} does not exist.` });
        }
        const ZoneID = siteCheck[0].ZoneID; // Get ZoneID from site

        // 2. Validate DroneID
        const [droneCheck] = await pool.execute('SELECT DroneID FROM Drone WHERE DroneID = ?', [DroneID]);
        if (droneCheck.length === 0) {
            console.log(`Report creation failed: DroneID ${DroneID} does not exist.`);
            return res.status(400).json({ error: `DroneID ${DroneID} does not exist.` });
        }
        
        // 3. Insert the new DebrisTask (Report)
        const taskSql = `
            INSERT INTO DebrisTask (SiteID, ZoneID, LocationCoords, EstimatedQuantity, Status) 
            VALUES (?, ?, ?, ?, 'Pending')
        `;
        const [taskResult] = await pool.execute(taskSql, [SiteID, ZoneID, LocationCoords, EstimatedQuantity]);
        const newTaskId = taskResult.insertId;

        // 4. Log the detection in DroneTask
        const logSql = `INSERT INTO DroneTask (TaskID, DroneID) VALUES (?, ?)`;
        await pool.execute(logSql, [newTaskId, DroneID]);
        
        console.log(`Successfully created new report with TaskID: ${newTaskId}`);
        res.status(201).json({ message: 'Debris report created successfully', TaskID: newTaskId });

    } catch (error) {
        console.error('Report creation error:', error);
        res.status(500).json({ error: 'Failed to create new report.' });
    }
    // --- END OF FIXED CODE ---
});


// ----------------------------------------------------------------------
// 6. DISPATCH ALGORITHM ROUTE (Protected by checkAuth & checkAdmin)
// ----------------------------------------------------------------------

// POST /api/dispatch/:taskId: Finds nearest truck and dispatches it
app.post('/api/dispatch/:taskId', checkAuth, checkAdmin, async (req, res) => {
    const { taskId } = req.params;
    
    try {
        console.log(`Attempting to dispatch TaskID: ${taskId}...`);
        // 1. Get the report's location and status
        const [reports] = await pool.execute(
            'SELECT LocationCoords, Status FROM DebrisTask WHERE TaskID = ?', 
            [taskId]
        );
        const report = reports[0];

        if (!report) {
            console.log(`Dispatch failed: Report ${taskId} not found.`);
            return res.status(404).json({ error: 'Report not found.' });
        }
        if (report.Status !== 'Pending') {
            console.log(`Dispatch failed: Report ${taskId} is already ${report.Status}.`);
            return res.status(400).json({ error: `Report status is already '${report.Status}'.` });
        }
        
        // 2. Get all available depots
        const [depots] = await pool.execute(
            'SELECT DepotID, DepotName, Coordinates, TrucksAvailable FROM TruckDepot WHERE TrucksAvailable > 0'
        );

        if (depots.length === 0) {
            console.log('Dispatch failed: No trucks available.');
            return res.status(404).json({ error: 'No trucks available for dispatch.' });
        }

        // 3. Find the nearest depot (THE CORE ALGORITHM)
        let nearestDepot = null;
        let minDistance = Infinity;

        for (const depot of depots) {
            // Calculate distance between report location and depot location
            const distance = getEuclideanDistance(report.LocationCoords, depot.Coordinates);
            if (distance < minDistance) {
                minDistance = distance;
                nearestDepot = depot;
            }
        }

        if (!nearestDepot) {
            console.log('Dispatch failed: Could not calculate nearest depot.');
            return res.status(500).json({ error: 'Could not calculate nearest depot.' });
        }
        
        console.log(`Nearest depot found: ${nearestDepot.DepotName}`);

        // 4. Update the records (Transaction needed, but using simple queries for demo)
        
        // Update 1: Decrement Truck Count
        const updateDepotSql = `UPDATE TruckDepot SET TrucksAvailable = TrucksAvailable - 1 WHERE DepotID = ?`;
        await pool.execute(updateDepotSql, [nearestDepot.DepotID]);
        
        // Update 2: Update Report Status
        const updateReportSql = `UPDATE DebrisTask SET Status = 'Dispatched', AssignedDepotID = ? WHERE TaskID = ?`;
        await pool.execute(updateReportSql, [nearestDepot.DepotID, taskId]);
        
        console.log(`Task ${taskId} successfully dispatched to ${nearestDepot.DepotName}.`);
        
        // 5. Respond
        res.json({ 
            message: 'Truck dispatched successfully!', 
            depot: nearestDepot.DepotName, 
            distance_units: minDistance.toFixed(4)
        });

    } catch (error) {
        console.error('Dispatch error:', error);
        res.status(500).json({ error: 'Server error during dispatch.' });
    }
});


// ----------------------------------------------------------------------
// 7. SERVER START
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`✅ Database pool created.`);
    console.log(`🚀 Server running on port ${PORT} (http://localhost:${PORT})`);
});
