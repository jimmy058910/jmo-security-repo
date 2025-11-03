// File handling with path traversal vulnerability

const fs = require('fs');
const path = require('path');

function readUserFile(userPath) {
  // VULNERABLE: Path traversal via unsanitized user input (line 10)
  fs.readFile(userPath, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading file:', err);
      return;
    }
    console.log('File contents:', data);
  });
}

function safeReadUserFile(userPath, baseDir) {
  // SAFE: Validate path is within allowed directory
  const resolvedPath = path.resolve(baseDir, userPath);

  if (!resolvedPath.startsWith(path.resolve(baseDir))) {
    throw new Error('Path traversal attempt detected');
  }

  fs.readFile(resolvedPath, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading file:', err);
      return;
    }
    console.log('File contents:', data);
  });
}

module.exports = { readUserFile, safeReadUserFile };
