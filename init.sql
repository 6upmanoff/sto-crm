DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS expenses CASCADE;
DROP TABLE IF EXISTS clients CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS companies CASCADE;

CREATE TABLE companies (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    trial_until DATE,
    subscription_until DATE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'lead', 'client')),
    company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE companies
ADD COLUMN lead_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    phone TEXT,
    car_number TEXT,
    car_model TEXT
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    service TEXT NOT NULL,
    price NUMERIC(12,2) NOT NULL DEFAULT 0,
    payment_type TEXT NOT NULL DEFAULT 'cash',
    status TEXT NOT NULL DEFAULT 'new',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE expenses (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO companies (name, trial_until, subscription_until, is_active)
VALUES
('Demo STO', CURRENT_DATE + INTERVAL '7 days', CURRENT_DATE + INTERVAL '30 days', true);

INSERT INTO users (full_name, email, password_hash, role, company_id)
VALUES
('Owner Demo', 'owner@demo.local', '$2y$12$67yppVnjWhp2oqvh9YbeH.PQt1dNWo2OH2x7QVthjopanw7PrZQsa', 'owner', NULL),
('Lead Demo', 'lead@demo.local', '$2y$12$h5GzyB13iWEooWyK2EW6SOxstn1/i/EXcmuSKEohR56adCkHyNJ9.', 'lead', NULL),
('Client Demo', 'client@demo.local', '$2y$12$fdEVq.wBGrkEpOA.mXE0IeQQfZjATHpwnl8Od7Q9GyDYcZGWY1mOe', 'client', 1);

UPDATE companies
SET lead_user_id = 2
WHERE id = 1;

INSERT INTO clients (company_id, name, phone, car_number, car_model)
VALUES
(1, 'Азамат', '+7 777 111 22 33', '123ABC04', 'Toyota Camry'),
(1, 'Нурлан', '+7 777 444 55 66', '456DEF04', 'Lada Granta');

INSERT INTO orders (company_id, client_id, service, price, payment_type, status)
VALUES
(1, 1, 'Замена шин', 8000, 'cash', 'done'),
(1, 2, 'Балансировка', 6000, 'transfer', 'done');

INSERT INTO expenses (company_id, name, amount)
VALUES
(1, 'Аренда', 50000),
(1, 'Расходные материалы', 12000);