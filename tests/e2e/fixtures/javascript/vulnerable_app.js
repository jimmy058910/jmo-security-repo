// Node.js application with known security vulnerabilities
const express = require('express');
const exec = require('child_process').exec;
const app = express();

// CWE-798: Hardcoded credentials
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'SuperSecret123!';

// CWE-78: Command Injection
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec(`ls ${cmd}`, (err, stdout) => {
        res.send(stdout);
    });
});

// CWE-73: External Control of File Name or Path
app.get('/file', (req, res) => {
    const filename = req.query.name;
    res.sendFile(filename);
});

// CWE-079: XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<html><body>Results for: ${query}</body></html>`);
});

// CWE-327: Weak crypto
const crypto = require('crypto');
function weakEncrypt(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// CWE-89: SQL Injection (conceptual)
const sqlite3 = require('sqlite3');
app.get('/user', (req, res) => {
    const db = new sqlite3.Database(':memory:');
    const username = req.query.username;
    // SQL injection vulnerability
    db.all(`SELECT * FROM users WHERE name = '${username}'`, (err, rows) => {
        res.json(rows);
    });
});

// CWE-601: Open Redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});

// Insecure server configuration
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
});
