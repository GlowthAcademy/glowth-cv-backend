require('dotenv').config();
const sendEmail = require('./utils/sendEmail');

sendEmail(
    'sacha@glowth.io',  // Replace with your email to test
    'Test Email from Glowth CV Generator',
    'Hello, this is a test email to verify Nodemailer setup.'
).then(() => {
    console.log('✅ Test email sent successfully');
}).catch((error) => {
    console.error('❌ Error sending test email:', error);
});

