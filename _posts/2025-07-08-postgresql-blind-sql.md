---
layout: post
title: "PostgreSQL Blind SQLi: Timing-Based Detection with pg_sleep()"
date: 2025-07-08
author: zerokoollabs
tags: [bugbounty, sqlinjection, blind-sqli, postgres, security, writeup]
---

# 🧠 PostgreSQL Blind SQLi: Timing-Based Injection with `pg_sleep`

**Challenge Type:** Blind SQL Injection  
**Lab Focus:** Detecting and exploiting a SQL injection when there's no visible output  
**Technique:** Time-based inference using PostgreSQL's `pg_sleep()` function  
**Vulnerability Location:** Cookie header  

---

## 🔍 Summary

This was my first foray into the world of **Blind SQL Injection**, and I was hooked by the subtlety of the challenge. There was no error message, no obvious output — just **silence**. Yet, with a little creativity and the right syntax, one realizes the silence speaks volumes.

---

## 💡 What Is Blind SQL Injection?

Blind SQLi occurs when the application is vulnerable to SQL injection but does **not return any data** to confirm the attack. You have to infer success by observing **timing**, **response changes**, or **external side-effects** (like DNS requests in OOB SQLi).

In this lab, the way to confirm whether SQL was injectable was to use a time delay, like this:

```sql
TrackingId=xyz'||pg_sleep(10)--
```

If the server **delayed its response by 10 seconds**, that meant my injected SQL **executed**, and I was communicating with the database — even though nothing was printed back. It's important to note that while a successful SQL `SLEEP` query clearly indicates access to the database, a failed attempt doesn't necessarily rule out other blind SQL injection techniques.

---

## 🧱 Cookie: A Simple Yet Powerful Attack Surface

The vulnerability was in the `TrackingId` cookie. Let’s back up:

> **What is a cookie?**

A cookie is just a **key-value pair** sent from the browser to the server with every request. For example:

```http
Cookie: TrackingId=Wn7CrRiCJUYBAHVr; session=abc123
```

Cookies are often used for session tracking, personalization, and analytics. But here’s the catch:  
**If not properly validated or signed**, cookies become an attacker’s playground.

---

## 🔓 How Cookie Tampering Violated the C.I.A. Model

In this lab, the app trusted the cookie value without verifying its **integrity**. That broke a foundational pillar of security:

### 🛡️ Integrity: Broken  
- I modified the cookie with a SQL payload
- The server accepted it and executed arbitrary SQL

### 🔐 Confidentiality: Potentially Broken  
- With further exploitation, I could retrieve secrets like user credentials

### 🧱 Availability: Temporarily Disrupted  
- Using `pg_sleep()` delayed the server response — a form of mild DoS

---

## 🔐 Cookie Integrity Protection (Missed Defense)

One way to prevent this would be to implement **integrity-protected cookies**, which include an HMAC signature.

**Example:**

```http
Cookie: auth=eyJ1c2VyIjoiam9obiIsInJvbGUiOiJhZG1pbiJ9.HMACsignature
```

The server can verify the signature before trusting the cookie’s contents.  
Without this, tampering is trivial — and that’s what allowed my SQLi to succeed.

---

## 🧠 Reverse Engineering the Silence

> “In Blind SQL, you have to really know what to expect…”

**Blind SQLi challenges aren’t just about crafting the right injection — they test your ability to contextualize both what you're doing and what you're _not_ seeing.** In a blind scenario, the absence of feedback is itself a clue. Each SQL server speaks its own dialect, and successfully triggering a delay doesn’t just confirm injection — it often reveals the underlying database engine. A well-placed `SLEEP` or `WAITFOR DELAY` isn't just a time bomb — it’s fingerprinting in disguise.

Here’s what I learned:

- You don’t need an error message or visible output to confirm a vulnerability
- You can use functions like `pg_sleep()` to cause **detectable behavior changes**
- A deep understanding of HTTP, cookies, SQL syntax, and timing attacks is essential

---

## 🧩 Syntax Pitfall: Why `' ; SELECT pg_sleep(10)--` Fails

**Attention to detail is essential in blind SQL injection.** Sometimes the “silence” isn’t the result of a successful injection — it’s just a syntax error. A stray typo or poorly aimed copy-paste can make you overlook a perfectly viable exploit.

Here’s one that tripped me up:

```sql
TrackingId='; SELECT pg_sleep(10)--
```

But that caused a syntax error. Why?

Because it **terminated the original query** prematurely and started a new one — which is often not allowed in web apps that only support **single-statement execution**.

✅ The correct payload was:

```sql
TrackingId=abc'||pg_sleep(10)--
```

This injected *within* the existing `WHERE` clause using string concatenation (`||`) and was syntactically valid.

---

## 🕒 Sleep Functions Across SQL Dialects

Knowing how to induce delays is crucial for **time-based blind SQL injection**. Here's a reference:

| **Database**  | **Sleep Function**         | **Example Payload**                           |
| ------------- | -------------------------- | --------------------------------------------- |
| PostgreSQL    | `pg_sleep(seconds)`        | `' \|\| pg_sleep(10)--`                       |
| MySQL         | `SLEEP(seconds)`           | `' OR SLEEP(10)--`                            |
| Microsoft SQL | `WAITFOR DELAY 'hh:mm:ss'` | `'; WAITFOR DELAY '0:0:10'--`                 |
| Oracle        | `DBMS_LOCK.SLEEP(seconds)` | `' OR 1=1; BEGIN DBMS_LOCK.SLEEP(10); END;--` |

💡 *Some require wrapping in a `BEGIN ... END;` block (like Oracle), and not all can be run in every context depending on permissions.*

---

### 💡 Pro Tip

If you’re not getting any delay:
- Try adjusting syntax (especially with Microsoft SQL and Oracle)
- Use tools like Burp Collaborator or Repeater timing
- Confirm that the database user has permission to run the sleep function

---

## 🔐 Remediation

To prevent this kind of attack:

- ✅ **Use parameterized queries** (prepared statements)
- ✅ **Avoid directly inserting user-controlled data into SQL queries**
- ✅ **Implement HMAC-signed cookies** or encrypted session tokens
- ✅ **Set `HttpOnly` and `Secure` flags** on cookies
- ✅ **Monitor for long SQL response times** (could indicate time-based SQLi attempts)

---

## ✅ Final Thoughts

What made this lab so engaging is that it’s **not about brute force** — it’s about **observation, timing, and inference**. The beauty of Blind SQLi is that even silence can speak, as long as you know how to listen.

```
"When nothing comes back… that’s not failure. It’s feedback."
```
