// config/mailer.js
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const path = require('path');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_PORT === '587', // True for 465, false for other ports like 587
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    },
    tls: {
       rejectUnauthorized: false
    }
});

/**
 * Renders an EJS email template.
 * @param {string} templateName - The name of the .ejs file in the 'emails' folder.
 * @param {object} data - Data to pass to the template.
 * @returns {Promise<string>} The rendered HTML content.
 */
const renderEmailTemplate = (templateName, data) => {
    return ejs.renderFile(path.join(__dirname, `../views/emails/${templateName}.ejs`), data);
};

/**
 * Sends a welcome/verification email.
 */
const sendWelcomeEmail = async (to, token) => {
    const verificationUrl = `http://targo.fun/verify-email?token=${token}`;
    try {
        const htmlContent = await renderEmailTemplate('welcomeEmail', { verificationUrl });
        await transporter.sendMail({
            from: `"کتابخانه مانگا تارگو" <${process.env.SMTP_USER}>`,
            to,
            subject: 'به تارگو خوش آمدید! حساب خود را تایید کنید',
            html: htmlContent
        });
    } catch (error) { console.error(`Error sending welcome email to ${to}:`, error); }
};

/**
 * Sends a password reset email.
 */
const sendPasswordResetEmail = async (to, token) => {
    const resetUrl = `http://targo.fun/reset-password?token=${token}`;
    try {
        const htmlContent = await renderEmailTemplate('passwordResetEmail', { resetUrl });
        await transporter.sendMail({
            from: `"کتابخانه مانگا تارگو" <${process.env.SMTP_USER}>`,
            to,
            subject: 'بازنشانی رمز عبور برای حساب تارگو شما',
            html: htmlContent
        });
    } catch (error) { console.error(`Error sending password reset email to ${to}:`, error); }
};

module.exports = { sendWelcomeEmail, sendPasswordResetEmail };
