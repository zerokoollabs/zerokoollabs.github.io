---
title: "Juice Shop: Password Reset Bypass via UI/API Mismatch"
description: "A walkthrough of how a misaligned frontend and backend allowed me to reset a high-privilege user's password in OWASP Juice Shop."
date: 2025-06-19
author: "Julian West"
tags: [OWASP, JuiceShop, CTF, BurpSuite, API, Security, LogicFlaw]
categories: [writeup, bug-analysis]
permalink: /juice-shop-password-reset-bypass/
layout: post
---

# 🧠 Bypassing Password Reset Protections in Juice Shop: A Deeper Dive

While working through OWASP Juice Shop, I uncovered a scenario that reflects a real-world logic flaw in account recovery systems — specifically, bypassing front-end restrictions to reset a high-privilege user's password.

---

## 🧪 Initial Setup

The challenge focused on the well-known account:  
📧 `bjoern.kimminich@gmail.com`

On the surface, the password reset UI disables all input fields — there’s **no way to initiate recovery** for this user through the frontend.

But the API behind the scenes told a different story.

---

## 🎯 The Exploit Path

Instead of going straight for the admin account, I began with a **valid user** that *did* have an active password reset option. From there:

1. I **captured the reset request** using Burp Suite  
2. I **modified the email field** in the request body to `bjoern.kimminich@gmail.com`  
3. Despite the UI being disabled, the backend accepted my forged request  
4. I guessed the security answer: `Zaya` (his pet's name)  
5. ✅ The answer worked — but login still failed  

This suggested the email *might not be the one tied to the active account*.

---

## 🔍 Recon and the Real Target

During a previous challenge, I had acquired a list of user emails through enumeration. I revisited it and tried:

📧 `bjoern@owasp.org`

Boom — this address triggered a functional password reset flow using the same security question (`What is your favorite pet’s name?`), which I already had the answer to.

From there:
- I forged a reset request
- Chose my own password
- Successfully logged in to the app as **bjoern@owasp.org**

---

## 🔐 Key Security Lessons

This challenge demonstrated a dangerous pattern:

> **Frontend restrictions ≠ backend security.**

Even though the UI disabled the form, the backend:
- Accepted alternate emails
- Processed password reset requests
- Relied on data that could be found through minimal research

---

## 🔎 Real-World Implications

While this was a lab, similar vulnerabilities can occur in production apps when:

- Email aliases or legacy accounts aren’t properly scoped
- Security questions remain active behind disabled forms
- APIs trust frontend input without verification
- There’s a disconnect between UI restrictions and backend logic

---

## 🧠 Final Thoughts

This wasn’t just about solving a Juice Shop challenge. It was a practical reminder that:
- Obscuring fields in the UI is **not** a secure control
- Alternate identifiers must be managed carefully
- Password reset flows should be audited thoroughly — especially for high-privilege accounts
