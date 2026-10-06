# PureGlow Solutions — Render + Supabase + Email

## What changed in this version
- WhatsApp handoff removed. After payment, the order details are emailed to the email the customer entered at checkout.
- A copy of every paid order is also emailed to the business (BUSINESS_EMAIL).
- Customers and orders are stored in Supabase (replaces the old DATABASE_URL / pg setup).
- Paystack webhook added so the email still goes out if the customer closes the page right after paying.
- Emails are sent exactly once per order; a "Resend confirmation email" button appears if sending fails.

## Setup (about 15 minutes)

### 1. Supabase
1. supabase.com > New project.
2. SQL Editor > New query > paste `supabase/schema.sql` > Run.
3. Project Settings > API: copy the **Project URL** and the **service_role** key (keep it secret — server only).

### 2. Email (Brevo — free, 300 emails/day, no domain needed)
1. Sign up at brevo.com.
2. Senders, Domains & Dedicated IPs > Senders > add `Pureglowsoltions25@gmail.com` (or any address you own) and click the verification link Brevo emails you.
3. SMTP & API > API Keys > create a key.
4. Set `EMAIL_FROM` to the verified sender address exactly.

### 3. Render environment variables
PAYSTACK_SECRET_KEY, AUTH_SESSION_SECRET (any long random string), SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, BREVO_API_KEY, EMAIL_FROM, EMAIL_FROM_NAME, BUSINESS_EMAIL.
Remove the old DATABASE_URL and PUREGLOW_WHATSAPP. Build: `npm install`. Start: `npm start`.

### 4. Paystack webhook
Paystack Dashboard > Settings > API Keys & Webhooks > Live Webhook URL:
`https://vioradetergents.onrender.com/api/payments/webhook`

### 5. Check it
Open `/health` on your site. It should show `"database": true, "paystack": true, "email": true`.
Then place a small test order and confirm the email arrives (check spam the first time).

## Flow
1. Customer pays through Paystack.
2. Server verifies with Paystack, saves the order in Supabase, emails the customer and the business.
3. Confirmation screen shows "sent to <email>".

## Recovering a payment that didn't show
If a customer paid but saw no confirmation, find the reference (starts with PGS-) in Paystack Dashboard > Transactions, then open:
`https://vioradetergents.com/?ref=PGS-XXXX`
The site verifies it with Paystack, saves the order in Supabase and sends the confirmation email.
