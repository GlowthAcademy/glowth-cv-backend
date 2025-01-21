const { createLogger, transports, format } = require('winston');

// Winston logger configuration
const logger = createLogger({
    level: 'info',  // Log only info level and above
    format: format.combine(
        format.timestamp(),
        format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new transports.File({ filename: 'logs/error.log', level: 'error' }),  // Log errors to a file
        new transports.File({ filename: 'logs/combined.log' })  // Log all messages
    ]
});

module.exports = logger;

