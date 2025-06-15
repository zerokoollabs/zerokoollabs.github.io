---
title: "Stack-Aware Hacking in OWASP Juice Shop"
date: 2025-06-14
author: "Julian West"
tags: [OWASP Juice Shop, JWT, Burp Suite, SQL Injection, Web Security, Penetration Testing]
categories: [Cybersecurity, Web App Security, Walkthroughs]
description: "How understanding the architecture of a modern web app helped me exploit an authentication bypass in OWASP Juice Shop using SQL injection and JWT manipulation."
slug: "stack-aware-hacking-juice-shop"
---

# 🧠 Stack-Aware Hacking in OWASP Juice Shop

I've been exploring **OWASP Juice Shop**, a sandboxed web application intentionally riddled with vulnerabilities. It's designed for hands-on learning — helping you practice spotting and exploiting security flaws in a controlled environment before encountering them in the wild.

But there's a trap: it’s easy to just go through the motions — copy known payloads, follow walkthroughs, and check off boxes. One of the first challenges I tackled was a classic **SQL injection**. Sure, you can paste `' OR 1=1--` into the login field, intercept the request using **Burp Suite**, and send it to **Repeater** to modify and replay the request. If the app is misconfigured (as is often the case in Juice Shop), you’ll bypass authentication and gain admin access.

Easy, right?

But here's the thing: **real-world penetration tests don’t come with instructions.** There’s no Morpheus calling your flip phone, telling you to go left or right to find the vulnerability. That’s where understanding the **stack** becomes a game changer.

## 🧱 Juice Shop Architectural Breakdown

| Component      | Technology         | Role                                                             |
| -------------- | ------------------ | ---------------------------------------------------------------- |
| **Frontend**   | Angular (SPA)      | Sends requests to backend APIs, handles UI, forms, login, etc.   |
| **Backend**    | Node.js + Express  | Hosts REST API routes and enforces (often broken) business logic |
| **Database**   | SQLite             | Stores users, orders, products, feedback — often insecurely      |
| **Web Server** | Express (built-in) | Listens on port 3000 and serves the entire application           |

When I saw this stack in play, it helped explain what I was seeing in Burp Suite — especially this line:

```
Authorization: Bearer eyJ0eXAiOiJKV1QiL...
```

If you know you're dealing with a modern single-page app built with Angular, Node.js, and JWT authentication, you know where to look. You expect:

- Token-based access control
- RESTful API calls
- JSON responses flowing back and forth

So capturing and replaying a JWT doesn’t feel like a magic trick — it becomes a **natural extension of how the stack works**. You're no longer blindly trying exploits; you're testing the logic of a system you understand.

Here is the raw "Authorization:  Bearer" that was received by SQL injection:

`Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDYtMTQgMDA6MzA6NTAuMzAxICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDYtMTQgMDA6MzA6NTAuMzAxICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc0OTg2MzAzNX0.CEBXDFGG0Zw4NlKBPPlGKvDG0xjYZuPHDLTWIQVXZuc-h3EbtVjZSOXfqM1VHHqQ1v2TX3TmdeoulK18GM6aTIxfLFCZD6LXZxo8OUWiVAqM7UsahJyPsZBkMquyDoOA42HuYEHZ_vtVltUVThERvg0M20pwxoB0cM1Z6YCYI6I`

By sending it over back to the server, via the Repeater function, you get the server to decode the token.  This is what the token looks like decoded.  You can decode it yourself via the website https://jwt.io/ ..... No password is required to do this.  Also note that the "Authorization: Bearer" Standard is defined in RFC 6750 and part of the broader HTTP authentication scheme. 

Here is the fully decoded token.  The fields are pretty self-explanatory:

`{`
  `"status": "success",`
  `"data": {`
    `"id": 1,`
    `"username": "",`
    `"email": "admin@juice-sh.op",`
    `"password": "0192023a7bbd73250516f069df18b500",`
    `"role": "admin",`
    `"deluxeToken": "",`
    `"lastLoginIp": "",`
    `"profileImage": "assets/public/images/uploads/defaultAdmin.png",`
    `"totpSecret": "",`
    `"isActive": true,`
    `"createdAt": "2025-06-14 00:30:50.301 +00:00",`
    `"updatedAt": "2025-06-14 00:30:50.301 +00:00",`
    `"deletedAt": null`
  `},`
  `"iat": 1749863035`
`}`

By injecting a SQL payload (`' OR 1=1--`), via the authentication field, I bypassed normal authentication and triggered the backend to issue me a **JWT token** with admin rights.  The server blindly trusted the token to decide the level of access I got when I used it.  To add further context, tokens like JWTs are purely Application Layer in the OSI Model, so it makes sense no password entry was needed.  

The server application did all work.  The server (1) extracted the token, (2) verified the token and (3) decoded the payload and authorized action, trusting the embedded "admin" role. 

To sum it up, I didn't log in to the system ..... I simply broke the query.

