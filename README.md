# 🐱‍💻 SQL Injection (SQLi) Cheatsheet

⚠️ **Alert:** This cheatsheet **does not cover the syntax for all SQL languages**. You can understand the logic here and apply it based on the specific SQL language you’re working with. For detailed syntax, visit the excellent [PortSwigger SQLi Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).  

---

## 📚 Table of Contents

1. [What is SQL Injection?](#what-is-sql-injection)
2. [Impact of SQL Injection Attacks](#impact-of-sql-injection-attacks)
3. [Types of SQL Injection](#types-of-sql-injection)
   - [In-Band SQL Injection](#1-in-band-sql-injection)
     - [Error-Based SQLi](#error-based-sql-injection)
     - [Union-Based SQLi](#union-based-sql-injection)
   - [Blind (Inferential) SQL Injection](#2-blind-inferential-sql-injection)
     - [Boolean-Based SQLi](#boolean-based-sql-injection)
     - [Time-Based SQLi](#time-based-sql-injection)
   - [Out-of-Band SQL Injection](#3-out-of-band-sql-injection)
4. [Advanced Blind SQLi Payloads](#advanced-blind-sqli-payloads)

---

## 📝 What is SQL Injection?

SQL Injection (SQLi) is a web security vulnerability where an attacker manipulates SQL queries made by an application to its database. Exploiting SQLi can lead to unauthorized access, data manipulation, and even remote code execution.

---

## 🚨 Impact of SQL Injection Attacks

SQLi attacks can severely affect:

1. **Confidentiality**: Unauthorized access to sensitive data (like usernames, passwords, and credit card details).
2. **Integrity**: Altering or deleting data.
3. **Availability**: Shutting down services or making data unavailable.
4. **Remote Code Execution**: In advanced cases, executing commands on the server.

---

## 💥 Types of SQL Injection

---

### 1️⃣ In-Band SQL Injection

In-band SQLi is the easiest and most common form of SQL injection, where the attacker uses the same communication channel to both launch the attack and retrieve results.

---

#### 🔹 Error-Based SQL Injection

Forces the database to generate errors, revealing sensitive information through error messages.

**Payloads:**
```sql
' AND CAST((SELECT 1) AS int)--
' AND CAST((SELECT password FROM users LIMIT 1) AS bool)--
' AND CAST((SELECT password FROM users LIMIT 1 OFFSET 0) AS bool)--
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--



