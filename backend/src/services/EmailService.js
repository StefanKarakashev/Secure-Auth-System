import nodemailer from 'nodemailer';

/**
 * EMAIL SERVICE
 * 
 * This service handles all email operations for the authentication system.
 * It supports multiple email providers and provides beautiful HTML templates.
 * 
 * Supported providers:
 * - Gmail (easiest for development)
 * - SendGrid (production recommended)
 * - AWS SES (production recommended)
 * - Any SMTP service
 */

class EmailService {
  constructor() {
    this.transporter = null;
    this.isConfigured = false;
    this.init();
  }

  /**
   * Initialize email transporter based on configuration
   */
  init() {
    try {
      const emailService = process.env.EMAIL_SERVICE;
      
      if (!emailService) {
        console.log('⚠️  Email service not configured. Emails will be logged to console.');
        return;
      }

      switch (emailService.toLowerCase()) {
        case 'gmail':
          this.setupGmail();
          break;
        case 'sendgrid':
          this.setupSendGrid();
          break;
        case 'aws-ses':
          this.setupAWSSES();
          break;
        case 'smtp':
          this.setupSMTP();
          break;
        default:
          console.log(`⚠️  Unknown email service: ${emailService}`);
      }
    } catch (error) {
      console.error('❌ Email service initialization failed:', error.message);
    }
  }

  /**
   * Setup Gmail with App Password
   */
  setupGmail() {
    const user = process.env.EMAIL_USER;
    const pass = process.env.EMAIL_PASSWORD;

    if (!user || !pass) {
      throw new Error('Gmail requires EMAIL_USER and EMAIL_PASSWORD environment variables');
    }

    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user,
        pass // This should be an App Password, not your regular password
      }
    });

    this.isConfigured = true;
    console.log('✅ Gmail email service configured');
  }

  /**
   * Setup SendGrid
   */
  setupSendGrid() {
    const apiKey = process.env.SENDGRID_API_KEY;

    if (!apiKey) {
      throw new Error('SendGrid requires SENDGRID_API_KEY environment variable');
    }

    this.transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      secure: false,
      auth: {
        user: 'apikey',
        pass: apiKey
      }
    });

    this.isConfigured = true;
    console.log('✅ SendGrid email service configured');
  }

  /**
   * Setup AWS SES
   */
  setupAWSSES() {
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    const region = process.env.AWS_REGION || 'us-east-1';

    if (!accessKeyId || !secretAccessKey) {
      throw new Error('AWS SES requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables');
    }

    this.transporter = nodemailer.createTransport({
      host: `email-smtp.${region}.amazonaws.com`,
      port: 587,
      secure: false,
      auth: {
        user: accessKeyId,
        pass: secretAccessKey
      }
    });

    this.isConfigured = true;
    console.log('✅ AWS SES email service configured');
  }

  /**
   * Setup custom SMTP
   */
  setupSMTP() {
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT) || 587;
    const secure = process.env.SMTP_SECURE === 'true';
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASSWORD;

    if (!host || !user || !pass) {
      throw new Error('SMTP requires SMTP_HOST, SMTP_USER, and SMTP_PASSWORD environment variables');
    }

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass }
    });

    this.isConfigured = true;
    console.log('✅ SMTP email service configured');
  }

  /**
   * Send welcome email with verification link
   */
  async sendWelcomeEmail(email, firstName, verificationToken) {
    const subject = 'Welcome! Please verify your email address';
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;
    
    const html = this.generateWelcomeEmailHTML(firstName, verificationUrl);
    const text = this.generateWelcomeEmailText(firstName, verificationUrl);

    return this.sendEmail(email, subject, html, text);
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(email, firstName, resetToken) {
    const subject = 'Reset your password';
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    
    const html = this.generatePasswordResetEmailHTML(firstName, resetUrl);
    const text = this.generatePasswordResetEmailText(firstName, resetUrl);

    return this.sendEmail(email, subject, html, text);
  }

  /**
   * Send login notification email
   */
  async sendLoginNotificationEmail(email, firstName, ipAddress, userAgent, location = 'Unknown') {
    const subject = 'New login to your account';
    const loginTime = new Date().toLocaleString();
    
    const html = this.generateLoginNotificationEmailHTML(firstName, ipAddress, userAgent, location, loginTime);
    const text = this.generateLoginNotificationEmailText(firstName, ipAddress, userAgent, location, loginTime);

    return this.sendEmail(email, subject, html, text);
  }

  /**
   * Core email sending method
   */
  async sendEmail(to, subject, html, text) {
    try {
      if (!this.isConfigured) {
        // Log email to console if not configured
        console.log('\n📧 EMAIL WOULD BE SENT:');
        console.log('─'.repeat(50));
        console.log(`To: ${to}`);
        console.log(`Subject: ${subject}`);
        console.log('Text Content:');
        console.log(text);
        console.log('─'.repeat(50));
        return { success: true, messageId: 'console-log' };
      }

      const mailOptions = {
        from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
        to,
        subject,
        text,
        html
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log(`✅ Email sent successfully to ${to}:`, result.messageId);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      console.error(`❌ Failed to send email to ${to}:`, error.message);
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }

  /**
   * Generate welcome email HTML template
   */
  generateWelcomeEmailHTML(firstName, verificationUrl) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to Our App</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #ffffff; padding: 30px; border: 1px solid #ddd; }
        .button { display: inline-block; background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; border-radius: 0 0 8px 8px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Welcome to Our App!</h1>
        </div>
        <div class="content">
          <h2>Hi ${firstName}!</h2>
          <p>Thanks for creating an account with us. To get started, please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center;">
            <a href="${verificationUrl}" class="button">Verify Email Address</a>
          </div>
          
          <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
          <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px;">
            ${verificationUrl}
          </p>
          
          <p><strong>This link will expire in 24 hours.</strong></p>
          
          <p>If you didn't create this account, please ignore this email.</p>
          
          <p>Welcome aboard!<br>The Team</p>
        </div>
        <div class="footer">
          <p>This email was sent from an automated system. Please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate welcome email text template
   */
  generateWelcomeEmailText(firstName, verificationUrl) {
    return `
    Welcome to Our App!
    
    Hi ${firstName}!
    
    Thanks for creating an account with us. To get started, please verify your email address by clicking the link below:
    
    ${verificationUrl}
    
    This link will expire in 24 hours.
    
    If you didn't create this account, please ignore this email.
    
    Welcome aboard!
    The Team
    `;
  }

  /**
   * Generate password reset email HTML template
   */
  generatePasswordResetEmailHTML(firstName, resetUrl) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #ffffff; padding: 30px; border: 1px solid #ddd; }
        .button { display: inline-block; background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; border-radius: 0 0 8px 8px; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Password Reset Request</h1>
        </div>
        <div class="content">
          <h2>Hi ${firstName}!</h2>
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          
          <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
          <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px;">
            ${resetUrl}
          </p>
          
          <div class="warning">
            <strong>⚠️ Security Notice:</strong>
            <ul>
              <li>This link will expire in 1 hour</li>
              <li>If you didn't request this reset, please ignore this email</li>
              <li>Your password will not change unless you click the link above</li>
            </ul>
          </div>
          
          <p>Stay secure!<br>The Team</p>
        </div>
        <div class="footer">
          <p>This email was sent from an automated system. Please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate password reset email text template
   */
  generatePasswordResetEmailText(firstName, resetUrl) {
    return `
    Password Reset Request
    
    Hi ${firstName}!
    
    We received a request to reset your password. Click the link below to create a new password:
    
    ${resetUrl}
    
    SECURITY NOTICE:
    - This link will expire in 1 hour
    - If you didn't request this reset, please ignore this email
    - Your password will not change unless you click the link above
    
    Stay secure!
    The Team
    `;
  }

  /**
   * Generate login notification email HTML template
   */
  generateLoginNotificationEmailHTML(firstName, ipAddress, userAgent, location, loginTime) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>New Login Detected</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #17a2b8; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #ffffff; padding: 30px; border: 1px solid #ddd; }
        .login-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; border-radius: 0 0 8px 8px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>New Login Detected</h1>
        </div>
        <div class="content">
          <h2>Hi ${firstName}!</h2>
          <p>We detected a new login to your account. Here are the details:</p>
          
          <div class="login-info">
            <strong>Login Details:</strong>
            <ul>
              <li><strong>Time:</strong> ${loginTime}</li>
              <li><strong>IP Address:</strong> ${ipAddress}</li>
              <li><strong>Location:</strong> ${location}</li>
              <li><strong>Device:</strong> ${userAgent}</li>
            </ul>
          </div>
          
          <p>If this was you, no action is needed.</p>
          
          <p><strong>If this wasn't you:</strong></p>
          <ol>
            <li>Change your password immediately</li>
            <li>Log out of all devices</li>
            <li>Contact our support team</li>
          </ol>
          
          <p>Stay secure!<br>The Team</p>
        </div>
        <div class="footer">
          <p>This email was sent from an automated system. Please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate login notification email text template
   */
  generateLoginNotificationEmailText(firstName, ipAddress, userAgent, location, loginTime) {
    return `
    New Login Detected
    
    Hi ${firstName}!
    
    We detected a new login to your account. Here are the details:
    
    Login Details:
    - Time: ${loginTime}
    - IP Address: ${ipAddress}
    - Location: ${location}
    - Device: ${userAgent}
    
    If this was you, no action is needed.
    
    If this wasn't you:
    1. Change your password immediately
    2. Log out of all devices
    3. Contact our support team
    
    Stay secure!
    The Team
    `;
  }

  /**
   * Test email configuration
   */
  async testConnection() {
    try {
      if (!this.isConfigured) {
        console.log('ℹ️  Email service not configured - emails will be logged to console');
        return { success: true, message: 'Console logging active' };
      }

      await this.transporter.verify();
      console.log('✅ Email service connection test successful');
      return { success: true, message: 'Connection successful' };
    } catch (error) {
      console.error('❌ Email service connection test failed:', error.message);
      return { success: false, message: error.message };
    }
  }
}

// Create singleton instance
const emailService = new EmailService();
export default emailService; 