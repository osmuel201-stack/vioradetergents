-- Run this once in Supabase: Dashboard > SQL Editor > New query > paste > Run

create table if not exists public.customers (
  id text primary key,
  name text not null,
  email text unique not null,
  phone text not null,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.orders (
  reference text primary key,
  customer_id text references public.customers(id) on delete set null,
  customer_name text not null,
  customer_email text not null,
  customer_phone text not null,
  fulfilment_method text not null,
  delivery_area text,
  delivery_address text,
  delivery_landmark text,
  delivery_map_link text,
  items jsonb not null,
  subtotal numeric(12,2) not null,
  fee numeric(12,2) not null,
  total numeric(12,2) not null,
  paid_at timestamptz,
  email_status text not null default 'pending',  -- pending | sending | sent | failed
  email_sent_at timestamptz,
  email_error text,
  created_at timestamptz not null default now()
);

-- Only the server (service_role key) touches these tables. RLS on + no policies
-- means the public/anon key can never read customers or orders.
alter table public.customers enable row level security;
alter table public.orders enable row level security;
