import express from 'express';
import mysql from 'mysql';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3306;

// Middleware
// app.use(cors({ origin: 'https://micron-eight.vercel.app/' }));
app.use(cors());
app.use(express.json()); // Built-in JSON body-parser
// Middleware to log errors
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});


// MySQL database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.log('Error connecting to MySQL:', err);
  } else {
    console.log('Connected to MySQL');
  }
});


// Check duplicates
app.post('/api/auth/check-duplicate', (req, res) => {
  const { phone } = req.body;

  // Query database to check for existing phone number
  db.query('SELECT * FROM users WHERE phone = ?', [phone], (err, results) => {
    if (err) {
      console.error('Error checking duplicate:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    // If results are not empty, the phone number exists
    if (results.length > 0) {
      return res.status(200).json({ exists: true });
    }

    // If no results, phone number does not exist
    return res.status(200).json({ exists: false });
  });
});

// User registration
app.post('/api/auth/signup', async (req, res) => {
  const { phone, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = password;
    // const hashedPassword = password;

    // Insert new user into the database
    db.query('INSERT INTO users (phone, password, role) VALUES (?, ?, ?)', [phone, hashedPassword, 'subscriber'], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      const userId = result.insertId; // Get the newly inserted user's ID

      // Generate JWT token
      const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '48h' });

      // Respond with token and success message
      res.status(201).json({ message: 'User registered successfully', token });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});



// Login route
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;

  // Query to find user by phone
  db.query('SELECT * FROM users WHERE phone = ?', [phone], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = results[0];

    // Compare the provided password with the stored hashed password
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid email or password' });
  }

    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '48h' });

    // Send the token and user role back to the client
    res.json({ message: 'Login successful', token, role: user.role }); // Include user role in the response
  });
});


// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token from "Bearer token"

  if (!token) return res.status(403).json({ message: 'Token missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};


// Apply protection to routes
app.get('/api/index', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/frontend/index.html');
});

app.get('/api/withdraw', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/frontend/withdraw.html');
});

app.get('/api/invest', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/frontend/invest.html');
});

app.get('/api/team', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/frontend/team.html');
});

app.get('/api/recharge', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/frontend/recharge.html');
});



// Protected route (example: user profile)
app.get('/api/profile', authenticateToken, (req, res) => {
  db.query('SELECT phone FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = results[0];
    res.json({
      phone: user.phone, // Return the phone number
      created_at: user.created_at
    });
  });
});



// Admin Sign-Up Route
app.post('/api/auth/admin-signup', async (req, res) => {
  const { phone, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = password;

    // Insert new admin into the database
    db.query('INSERT INTO users (phone, password, role) VALUES (?, ?, ?)', [phone, hashedPassword, 'admin'], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      const userId = result.insertId; // Get the newly inserted admin's ID

      // Generate JWT token
      const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '48h' });

      // Respond with token and success message
      res.status(201).json({ message: 'Admin registered successfully', token });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// total users
app.get('/api/admin/total-users', (req, res) => {
  db.query('SELECT COUNT(*) AS totalUsers FROM users', (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    const totalUsers = results[0].totalUsers;
    res.json({ totalUsers });
  });
});


app.get('/api/admin/profile', authenticateToken, (req, res) => {
  console.log("Admin profile requested");
  const adminId = req.user.id;
  db.query('SELECT phone FROM users WHERE id = ? AND role = "admin"', [adminId], (err, results) => {
    if (err || results.length === 0) {
      console.log("Admin not found or database error", err);
      return res.status(500).json({ message: 'Admin not found' });
    }
    res.json({ phone: results[0].phone });
  });
});

// fetch allusers
app.get('/api/admin/users', (req, res) => {
  db.query('SELECT id, phone, role FROM users', (err, results) => {
      if (err) {
          return res.status(500).json({ message: 'Database error' });
      }
      res.json(results);
  });
});




// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
