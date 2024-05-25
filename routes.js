// routes.js
const express = require('express');
const router = express.Router();
const db = require('./db');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();
const SECRET_KEY = '3f10abfac9c733bf49201e5148b27ee1b5ca5730fd54c292663892755ac72e5d';
// app.use(express.json());




// User registration endpoint
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
  
    if (!name || !email || !password) {
      return res.status(400).send('Name, email, and password are required');
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
  
    const sql = 'INSERT INTO registered_users (name, email, password) VALUES (?, ?, ?)';
    db.query(sql, [name, email, hashedPassword], (err, result) => {
      if (err) {
        console.error('Error inserting into the database:', err);
        return res.status(500).send('Server error');
      }
  
      res.status(201).send('User registered successfully');
    });
  });

// User login endpoint
router.post('/auth', async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).send('Email and password are required');
    }
  
    const sql = 'SELECT * FROM registered_users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
      if (err) {
        console.error('Error querying the database:', err);
        return res.status(500).send('Server error');
      }
  
      if (results.length === 0) {
        return res.status(401).send('Invalid email or password');
      }
  
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
  
      if (!passwordMatch) {
        return res.status(401).send('Invalid email or password');
      }
  
 // Generate JWT token
 const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });  
      res.status(200).send({
        message: 'Authentication-Successful',
        token
      });
    });
  });

  // Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(403).send('A token is required for authentication');
    }
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
    } catch (err) {
      return res.status(401).send('Invalid token');
    }
    return next();
  };

  // Protected route example
  router.get('/protected', verifyToken, (req, res) => {
    res.status(200).send('This is a protected route');
  });

//--------------------- Other Routes ---------------------
//--------------------- ____________ ---------------------

// Create
router.post('/create',verifyToken, (req, res) => {
    const { name, email, phone, country, nationality, languages_speaking } = req.body;
    const sql = `INSERT INTO users (name, email, phone, country, nationality, languages_speaking) VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(sql, [name, email, phone, country, nationality, languages_speaking], (err, result) => {
        if (err) {
            return res.status(500).send('Error creating user');
        }
        return res.send('Data successfully created!');
    });
});

// Read all users
router.get('/users',verifyToken, (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving users');
        }
        return res.json(results);
    });
});

// Read one user
router.get('/read/:id',verifyToken,(req, res) => {
    const id = req.params.id;
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).send('Error reading user');
        }
        if (result.length === 0) {
            return res.status(404).send('User not found');
        }
        return res.json(result[0]);
    });
});

// Update
router.put('/update/:id',verifyToken,(req, res) => {
    const id = req.params.id;
    const { name, email, phone, country, nationality, languages_speaking } = req.body;
    const sql = `UPDATE users SET name = ?, email = ?, phone = ?, country = ?, nationality = ?, languages_speaking = ? WHERE id = ?`;
    db.query(sql, [name, email, phone, country, nationality, languages_speaking, id], (err, result) => {
        if (err) {
            return res.status(500).send('Error updating user');
        }
        return res.send('Data successfully updated!');
    });
});

// Delete
router.delete('/delete/:id',verifyToken,(req, res) => {
    const id = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).send('Error deleting user');
        }
        return res.send('Data successfully deleted!');
    });
});
module.exports = router;
