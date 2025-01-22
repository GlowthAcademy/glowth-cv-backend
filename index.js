// Load environment variables at the very top
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const pool = require('./config/db');
const logger = require('./utils/logger'); // Import Winston logger

// ==============================
// 🛠️ Database Connection Debugging
// ==============================

pool.connect()
    .then(() => logger.info('✅ Successfully connected to PostgreSQL database'))
    .catch(err => logger.error('❌ Database connection error:', err));

// ==============================
// 🚀 Initialize Express App
// ==============================

const app = express();

// ==============================
// 🔒 Apply Security Middleware
// ==============================

// Helmet for setting secure HTTP headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "trusted-scripts.com"],  // Allow scripts from self and trusted source
            objectSrc: ["'none'"],  // Block object embeds
            upgradeInsecureRequests: []  // Upgrade HTTP requests to HTTPS
        }
    },
    frameguard: { action: 'deny' }, // Prevent clickjacking
    xssFilter: true,                 // Enable XSS protection
    noSniff: true,                    // Prevent MIME sniffing
    hsts: { maxAge: 31536000, includeSubDomains: true },  // Force HTTPS
    referrerPolicy: { policy: 'no-referrer' }
}));

// Morgan for request logging (sends logs to Winston)
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// ==============================
// 🛡️ CORS Setup (Cross-Origin Resource Sharing)
// ==============================

const allowedOrigins = [
    'http://localhost:3000',  // React app during development
    'https://your-production-domain.com'  // Production frontend
];

app.use(cors({
    origin: (origin, callback) => {
        logger.info(`Incoming request from origin: ${origin}`);

        if (!origin || allowedOrigins.includes(origin)) {
            logger.info(`✅ Allowed request from: ${origin}`);
            callback(null, true);
        } else {
            logger.warn(`❌ CORS policy violation from: ${origin}`);
            callback(new Error('CORS policy violation: Unauthorized request'));
        }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true
}));

// Enable JSON parsing for incoming requests
app.use(express.json());

// ==============================
// 🛡️ Rate Limiting (Prevents Brute-Force Attacks)
// ==============================

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes window
    max: 10,  // Limit each IP to 10 requests per window
    message: 'Too many requests, please try again later',
    handler: (req, res) => {
        logger.warn(`⚠️ Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({ message: 'Too many requests, please try again later' });
    }
});

// Apply rate limiting to sensitive routes
app.use('/api/users/login', limiter);
app.use('/api/users/register', limiter);

// ==============================
// ✅ Import and Use Routes
// ==============================

const userRoutes = require('./routes/userRoutes');
app.use('/api/users', userRoutes);

// ==============================
// 🚀 Test Route (Basic Health Check)
// ==============================

app.get('/', (req, res) => {
    logger.info('✅ Test route accessed: /');
    res.send('Glowth CV Generator API is running securely...');
});

// ==============================
// 🌐 Global Error Handling Middleware
// ==============================

app.use((err, req, res, next) => {
    logger.error(`🔥 Server error: ${err.message}`);
    res.status(500).json({ message: 'Internal server error' });
});

// ==============================
// 🚀 Start Server
// ==============================

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
    logger.info(`✅ Server running on port ${PORT}`);
});

