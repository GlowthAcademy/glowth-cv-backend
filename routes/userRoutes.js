const { body, validationResult } = require('express-validator');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');
const pool = require('../config/db');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// User Registration
router.post(
    '/register',
    [
        body('email').isEmail().withMessage('Please enter a valid email'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (userExists.rows.length > 0) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);

            res.status(201).json({ message: 'User registered successfully' });
        } catch (error) {
            console.error('Registration error:', error.message);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
);

// User Login
router.post(
    '/login',
    [
        body('email').isEmail().withMessage('Please enter a valid email'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (user.rows.length === 0) {
                return res.status(400).json({ message: 'Invalid email or password' });
            }

            const isMatch = await bcrypt.compare(password, user.rows[0].password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid email or password' });
            }

            const token = jwt.sign(
                { id: user.rows[0].id },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.json({ message: 'Login successful', token });
        } catch (error) {
            console.error('Login error:', error.message);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
);

// Protected route: Get user profile
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        console.log(`Fetching profile for user ID: ${req.user.id}`);

        const userQuery = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.user.id]);
        if (userQuery.rows.length === 0) {
            console.log(`User with ID ${req.user.id} not found.`);
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(userQuery.rows[0]);
    } catch (error) {
        console.error('Profile fetch error:', error.message);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Update user profile
router.put('/update', authMiddleware, async (req, res) => {
    const { name, email, password } = req.body;
    const userId = req.user.id;

    try {
        if (!name && !email && !password) {
            return res.status(400).json({ message: 'Please provide at least one field to update.' });
        }

        const userQuery = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

        if (userQuery.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        let updatedName = name || userQuery.rows[0].name;
        let updatedEmail = email || userQuery.rows[0].email;
        let updatedPassword = userQuery.rows[0].password;

        if (password) {
            updatedPassword = await bcrypt.hash(password, 10);
        }

        await pool.query(
            'UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4',
            [updatedName, updatedEmail, updatedPassword, userId]
        );

        res.status(200).json({ message: 'Profile updated successfully' });

    } catch (error) {
        console.error('Profile update error:', error.message);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Request password reset
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        if (!email) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }

        const userQuery = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userQuery.rows.length === 0) {
            return res.status(400).json({ message: 'User with this email does not exist' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiry = new Date(Date.now() + 3600000);  // Token valid for 1 hour

        await pool.query('UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
                         [resetToken, tokenExpiry, email]);

        const resetLink = `${process.env.RESET_LINK}/${resetToken}`;
        await sendEmail(email, 'Password Reset Request', `Click this link to reset your password: ${resetLink}`);

        res.status(200).json({ message: 'Password reset link sent to your email' });
    } catch (error) {
        console.error('Error requesting password reset:', error.message);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Reset password
router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        if (!newPassword) {
            return res.status(400).json({ message: 'Please provide a new password' });
        }

        const userQuery = await pool.query(
            'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()', 
            [token]
        );

        if (userQuery.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2',
            [hashedPassword, token]
        );

        res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

module.exports = router;

