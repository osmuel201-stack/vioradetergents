# PureGlow Solutions — Render deployment

## What is included
- PureGlow storefront frontend
- Real Paystack server-side transaction initialization and verification
- Customer signup/login with hashed passwords
- PostgreSQL customer/order storage
- Cape Coast delivery fields
- Optional Google Maps link for the delivery point
- Post-payment WhatsApp handoff with the paid order, customer details and delivery location
- Uploaded product image added to the product gallery (the original hero image remains the hero)

## Render environment variables
Set these in the Render Web Service:

- `PAYSTACK_SECRET_KEY` — your Paystack secret key (`sk_live_...` for live payments)
- `AUTH_SESSION_SECRET` — a long random string used to sign customer sessions
- `DATABASE_URL` — PostgreSQL connection string (Supabase/Postgres or another PostgreSQL provider)
- `PUREGLOW_WHATSAPP` — WhatsApp number in international format without `+`, e.g. `233597601733`

Do not put the Paystack secret key in GitHub or frontend JavaScript.

## Render settings
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`

The service serves the frontend and API from the same origin.

## Database
The server automatically creates these tables on startup:
- `customers`
- `orders`

A persistent PostgreSQL database is required for real customer accounts and durable order records. Do not rely on a local JSON/SQLite file on a normal Render web service for production customer data.

## Customer order flow
1. Customer adds products to cart.
2. Customer can create an account or continue as a guest.
3. Customer enters their WhatsApp/phone number.
4. For delivery, customer enters area + address and may paste a Google Maps link.
5. Render initializes the Paystack transaction using the secret key.
6. Paystack handles the payment.
7. Render verifies the transaction directly with Paystack.
8. The successful order is stored in PostgreSQL.
9. Customer gets a button to open WhatsApp with the paid order and delivery details pre-filled.
10. Customer taps Send; they can also share their live WhatsApp location if needed.
