/**
 * INTENTIONALLY VULNERABLE Node.js/Express application.
 * FOR TESTING PURPOSES ONLY — DO NOT DEPLOY.
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(express.json());

// A02: Hardcoded secret
const apiKey = "sk-abc123verysecretkey";
const JWT_SECRET = "secret";

// ── A03: SQL Injection ────────────────────────────────────────────────────────
app.get('/user', (req, res) => {
    const id = req.query.id;
    const conn = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
    // VULNERABLE: string concatenation in query
    conn.query("SELECT * FROM users WHERE id = " + id, (err, results) => {
        res.json(results);
    });
});

// ── A03: XSS ─────────────────────────────────────────────────────────────────
app.get('/greet', (req, res) => {
    const name = req.query.name;
    // VULNERABLE: user input in innerHTML equivalent
    res.send(`<h1>Hello ${name}</h1>`);
});

// ── A03: Command Injection ────────────────────────────────────────────────────
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // VULNERABLE: user input in exec
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// ── A10: SSRF ─────────────────────────────────────────────────────────────────
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    // VULNERABLE: user-controlled URL
    const response = await axios.get(url);
    res.send(response.data);
});

// ── A01: Path Traversal ───────────────────────────────────────────────────────
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: no path sanitisation
    fs.readFile(`/uploads/${filename}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

// ── A07: Weak JWT ─────────────────────────────────────────────────────────────
app.post('/login', (req, res) => {
    const { username } = req.body;
    // VULNERABLE: weak hardcoded secret
    const token = jwt.sign({ username }, "secret");
    res.json({ token });
});

// ── A02: Insecure TLS ─────────────────────────────────────────────────────────
const https = require('https');
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// ── A05: CORS misconfiguration ────────────────────────────────────────────────
const cors = require('cors');
app.use(cors({ origin: '*' }));  // VULNERABLE: wildcard CORS

app.listen(3000);
