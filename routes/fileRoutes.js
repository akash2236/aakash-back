const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { AES } = require('crypto-js');

// Set up storage engine
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = './uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Upload Encrypted File
router.post('/upload', verifyToken, upload.single('file'), (req, res) => {
  try {
    const userKey = req.body.key; // Client-side key
    const filePath = req.file.path;
    const fileData = fs.readFileSync(filePath);

    // Encrypt file before storing
    const encrypted = AES.encrypt(fileData.toString(), userKey).toString();

    fs.writeFileSync(filePath + '.enc', encrypted);
    fs.unlinkSync(filePath); // Remove original

    res.status(201).json({
      success: true,
      message: 'File uploaded and encrypted successfully',
      file: {
        name: req.file.filename + '.enc',
        size: req.file.size,
        path: filePath + '.enc'
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ success: false, error: 'File upload failed' });
  }
});

module.exports = router;