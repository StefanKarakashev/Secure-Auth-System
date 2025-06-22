# Email Setup Guide

Configure email services for password reset and verification emails.

## Development (Console Logging)

By default, emails are logged to the console instead of being sent. This is useful for development and testing.

## Gmail Setup

1. Enable 2-Factor Authentication on your Google account
2. Go to Google Account → Security → 2-Step Verification → App passwords
3. Create an app password for "Mail"
4. Add to your `.env` file:

```env
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=your-email@gmail.com
```

## SendGrid (Recommended for Production)

1. Create a free SendGrid account
2. Generate an API key with full access
3. Verify your sender email address
4. Add to your `.env` file:

```env
EMAIL_SERVICE=sendgrid
SENDGRID_API_KEY=SG.your-api-key-here
EMAIL_FROM=noreply@yourdomain.com
```

## Custom SMTP

For other email providers:

```env
EMAIL_SERVICE=smtp
SMTP_HOST=smtp.yourmailserver.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-username
SMTP_PASSWORD=your-password
EMAIL_FROM=noreply@yourdomain.com
```

## Testing

Start your server and register a new user to test email functionality. 