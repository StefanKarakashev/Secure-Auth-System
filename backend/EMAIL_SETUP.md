# Email Service Setup Guide

This guide will help you set up email services for your authentication system. You have several options depending on your needs.

## 🚀 Quick Start (Console Logging)

If you don't set up any email service, emails will be logged to the console. This is perfect for development and testing.

**No configuration needed!** Just register a user and check your server console.

---

## 📧 Option 1: Gmail (Easiest for Development)

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account settings
2. Enable 2-Factor Authentication if not already enabled

### Step 2: Generate App Password
1. Go to Google Account → Security → 2-Step Verification → App passwords
2. Select "Mail" and "Other (custom name)" 
3. Enter "Auth System" as the name
4. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)

### Step 3: Configure Environment
Create a `.env` file in your backend folder:

```env
# Gmail Configuration
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=abcd efgh ijkl mnop
EMAIL_FROM=your-email@gmail.com
```

### Step 4: Test
```bash
npm run dev
```

Register a new user and check your email!

---

## 🏢 Option 2: SendGrid (Production Recommended)

### Step 1: Create SendGrid Account
1. Go to [SendGrid](https://sendgrid.com/)
2. Sign up for a free account (100 emails/day free)

### Step 2: Get API Key
1. Go to Settings → API Keys
2. Create API Key with "Full Access"
3. Copy the API key (starts with `SG.`)

### Step 3: Verify Sender
1. Go to Settings → Sender Authentication
2. Verify a single sender email address

### Step 4: Configure Environment
```env
# SendGrid Configuration
EMAIL_SERVICE=sendgrid
SENDGRID_API_KEY=SG.your-api-key-here
EMAIL_FROM=noreply@yourdomain.com
```

---

## ☁️ Option 3: AWS SES (Production Recommended)

### Step 1: Setup AWS Account
1. Create AWS account if you don't have one
2. Go to AWS SES console

### Step 2: Verify Email/Domain
1. Verify your sending email address or domain
2. Request production access (starts in sandbox mode)

### Step 3: Create IAM User
1. Go to IAM → Users → Create User
2. Attach policy: `AmazonSESFullAccess`
3. Create access keys

### Step 4: Configure Environment
```env
# AWS SES Configuration
EMAIL_SERVICE=aws-ses
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
EMAIL_FROM=noreply@yourdomain.com
```

---

## 🔧 Option 4: Custom SMTP

For any other email provider (Outlook, Yahoo, custom mail server):

```env
# Custom SMTP Configuration
EMAIL_SERVICE=smtp
SMTP_HOST=smtp.yourmailserver.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-username
SMTP_PASSWORD=your-password
EMAIL_FROM=noreply@yourdomain.com
```

### Common SMTP Settings:

**Outlook/Hotmail:**
```env
SMTP_HOST=smtp.live.com
SMTP_PORT=587
SMTP_SECURE=false
```

**Yahoo:**
```env
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_SECURE=false
```

---

## 🧪 Testing Your Email Setup

### Method 1: Register a New User
1. Start your server: `npm run dev`
2. Register with a real email address using Postman/frontend
3. Check your email inbox

### Method 2: Test Endpoint (Coming Soon)
We can add a test endpoint if needed.

---

## 📧 Email Templates

Your system sends beautiful HTML emails for:

- **Welcome Email**: Sent after registration with verification link
- **Password Reset**: Sent when user requests password reset  
- **Login Notification**: Sent for new device logins (optional)

All emails are:
- ✅ Mobile responsive
- ✅ Professional design  
- ✅ Both HTML and plain text versions
- ✅ Security-focused messaging

---

## 🔒 Security Best Practices

1. **Never commit email credentials** to version control
2. **Use App Passwords** for Gmail (not your main password)
3. **Rotate API keys** regularly in production
4. **Set up SPF/DKIM/DMARC** records for your domain
5. **Monitor email deliverability** in production

---

## 🐛 Troubleshooting

### "Username and Password not accepted"
- Gmail: Make sure you're using an App Password, not your regular password
- Outlook: Enable "Less secure app access"

### "Daily sending quota exceeded"
- Gmail: 500 emails/day limit
- SendGrid Free: 100 emails/day limit
- Upgrade to paid plan for higher limits

### Emails going to spam
- Set up proper DNS records (SPF, DKIM, DMARC)
- Use a verified domain
- Include unsubscribe links
- Monitor your sender reputation

### "Connection timeout"
- Check firewall settings
- Verify SMTP host and port
- Try different ports (587, 465, 25)

---

## 🎯 Recommendations

- **Development**: Gmail (easiest setup)
- **Production**: SendGrid or AWS SES (better deliverability)
- **High Volume**: AWS SES (most cost-effective for scale)

Need help? Check the console logs - they'll show exactly what's happening with your email service! 