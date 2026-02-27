// Sample Express.js application with XSS vulnerability

const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ... other middleware and routes ...

// Route handler with XSS vulnerability (line 42)
app.get('/search', (req, res) => {
  const userInput = req.query.q;

  // VULNERABLE: User input directly rendered without sanitization (line 42)
  res.send(userInput);
});

// ... more routes ...

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
