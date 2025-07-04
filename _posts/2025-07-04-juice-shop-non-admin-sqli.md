---
layout: post
title: "Juice Shop SQL Injection: Non-Admin Forced Login"
date: 2025-07-04
tags:
  - owasp
  - sql-injection
  - juice-shop
  - jwt
  - bug-bounty
  - writeup
---

# 🧠 SQL Injection: Forced Login as Non-Admin in Juice Shop

## Summary

While exploring SQL injection vulnerabilities in OWASP Juice Shop, I successfully exploited the login mechanism to authenticate as a **non-admin user** without knowing their password. This mirrors a real-world scenario where attackers target mid-privileged accounts for lateral movement or data access — often avoiding detection that would come with admin login.  The login mechanism lacks basic protections against input tampering.

The exploit takes advantage of a misconfigured interaction between the front-end and back-end, where the login form allows raw SQL arguments to be passed directly to the database without proper validation or sanitization.

There are a number of tests to determine whether a SQL injection is even possible in a target system.  One of the simplest is to enter a simple ' in the email field of the login page while intercepting the packet on a tool like Burp Suite.  If you receive an error or other kind of anomaly, the response packet will often reveal the SQL database engine (e.g., Oracle, MySQL, SQLite, etc.) based on the error message. 

So, let's get into the details of this particular Juice-Shop hack:

---
## 💉 Injection Used

### Email Field:
```
user001@juice-shop'-- 
```
### Password Field:
```
anything
```

NOTE:  In SQL, `--` is a comment indicator that tells the database to ignore the rest of the line. This means the password condition (`AND password = ...`) is never evaluated.  This comment sequence tells the SQL interpreter to ignore everything that follows, effectively bypassing the password check entirely.

What was entered in those authentication fields amounts to the following SQL Query:

```sql
SELECT * FROM Users WHERE email = 'user001@juice-shop'-- ' AND password = 'anything';
```

The query instructs the SQL engine to return the user record for `'user001@juice-shop'`, ignoring the password clause entirely.  The `--` comment nullifies the password check.  As long as the user exists in the queried database, the user has logged into the system.

---
## 🧪 Steps to Reproduce

1. Launch OWASP Juice Shop in your lab environment.
2. Open the login page.
3. In the email field, enter: `user001@juice-shop'--`
4. Enter anything in the password field.
5. Observe a successful login and inspect the issued JWT.

---

## 🛠️ Behavior Observed

- The app logged me in successfully as `user001@juice-shop`.
- A JWT token was issued for this user.
- I was able to access the user's basket and profile data.
- This bypassed all credential checks, and I did **not** need to elevate to admin.

---

## 🎯 Significance

- This attack demonstrates a **targeted authentication bypass** — not just a generic `OR 1=1` login.
- It's especially relevant in bug bounty scenarios where an attacker might aim for:
  - Access to support dashboards
  - Viewing PII (Personally Identifiable Information) or usage data of other users
  - Staying stealthy by avoiding admin-level alerts

---

## 🧠 Reflection

Even though Juice Shop didn’t grant credit for this specific injection, the exploit is **valid and valuable**. It deepens understanding of how SQL injection can be surgically applied, especially against lightly defended entry points.

---

## 🔐 Real-World Prevention

- Always use parameterized queries
- Avoid direct string interpolation in SQL
- Validate and sanitize user input
- Monitor for odd login patterns (e.g., many logins without password resets)

Let’s wrap up by examining how this attack could have been prevented using parameterized queries — a best practice for securing SQL statements against injection.

---

## 🛡️ Parameterized Queries: A Python Sample

A **parameterized query** is a safe coding technique used to run SQL queries **without mixing user input directly into the SQL code**. This creates a kind of front-end _shield_, preventing user-supplied data from being executed as SQL commands — which is a key defense against SQL injection. 

Below is an example written in Python. It uses **SQL placeholders** and a Python data structure known as a **tuple**. A tuple is similar to a list, but **immutable** (it can't be changed after it's created). It's defined using parentheses `()` rather than square brackets `[]`:

`cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))`

Here’s what’s happening:

- The `?` symbols are **SQL placeholders** — not variables — used by the database driver (like `sqlite3` or `pyodbc`).
- `(email, password)` is a **tuple of values** passed separately to the query.
- Python sends the query and the values independently to the database, which **plugs in the values as raw data — not as SQL code**.
    
This separation ensures that even if a user tries to inject SQL (e.g., by entering something like `user'--`), it will be treated as harmless text, not executable SQL. This is a simple but powerful way to block one of the most dangerous web vulnerabilities: **SQL Injection**.