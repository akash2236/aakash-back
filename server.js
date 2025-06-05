require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
const allowedOrigins = ['http://localhost:5173', 'http://localhost:3000'];
app.use(express.json());
app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// Enhanced Multer config for file uploads with limits
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Add any file type restrictions if needed
    cb(null, true);
  }
});

// Enhanced Nodemailer transporter with retry logic
let transporter;
let transporterInitialized = false;

const createTransporter = async (retries = 3) => {
  try {
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: process.env.EMAIL_PORT || 587,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      tls: { rejectUnauthorized: false },
      pool: true,
      maxConnections: 5,
      maxMessages: 100
    });
    
    await transporter.verify();
    transporterInitialized = true;
    console.log('✅ Email transporter ready');
  } catch (err) {
    console.error('❌ Failed to initialize email transporter:', err.message);
    if (retries > 0) {
      console.log(`Retrying... (${retries} attempts left)`);
      await new Promise(resolve => setTimeout(resolve, 5000));
      await createTransporter(retries - 1);
    }
  }
};

createTransporter(); // Initialize transporter

// Enhanced password hashing with better salt handling
const hashPassword = (password) => {
  const salt = process.env.PASSWORD_SALT || 'default-salt-should-be-changed';
  return crypto.createHash('sha256')
    .update(password + salt)
    .digest('hex');
};

// OTP generation with crypto-safe method
const generateOTP = () => {
  const buffer = crypto.randomBytes(3);
  const otp = 100000 + (buffer.readUIntBE(0, 3) % 900000);
  return otp.toString();
};

// Enhanced in-memory OTP cache with cleanup
const signupOtpCache = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [email, data] of signupOtpCache.entries()) {
    if (data.expires < now) signupOtpCache.delete(email);
  }
}, 60 * 1000);

// Enhanced MongoDB connection with retry logic
const connectWithRetry = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10
    });
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    console.log('Retrying in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  }
};

connectWithRetry();

// Enhanced User Schema with validation
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: { type: String, required: true, select: false },
  profileImage: { 
    type: String, 
    default: 'https://via.placeholder.com/150',
    validate: [validator.isURL, 'Please provide a valid URL']
  },
  otp: { type: String, select: false },
  otpExpires: { type: Date, select: false },
  isVerified: { type: Boolean, default: false },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

// Enhanced File Schema with validation
const fileSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  originalName: { 
    type: String, 
    required: true,
    trim: true
  },
  filename: { 
    type: String, 
    required: true,
    unique: true
  },
  size: { 
    type: Number, 
    required: true,
    min: 1
  },
  uploadDate: { type: Date, default: Date.now },
  encrypted: { type: Boolean, default: true },
  mimeType: String
});

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// Enhanced token verification middleware with refresh token support
function verifyToken(req, res, next) {
  let token;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer')) {
    token = authHeader.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'You are not logged in!',
      code: 'NO_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Session expired. Please login again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid token',
      code: 'INVALID_TOKEN'
    });
  }
}

// Enhanced send email function with retry logic
const sendEmail = async (mailOptions, retries = 2) => {
  if (!transporterInitialized) await createTransporter();
  
  try {
    await transporter.sendMail({
      ...mailOptions,
      from: mailOptions.from || `"AetherVault" <${process.env.EMAIL_USER}>`
    });
    console.log(`📧 Email sent to ${mailOptions.to}`);
    return true;
  } catch (err) {
    console.error('❌ Email sending failed:', err.message);
    if (retries > 0) {
      console.log(`Retrying... (${retries} attempts left)`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      return sendEmail(mailOptions, retries - 1);
    }
    return false;
  }
};

// Routes

// Enhanced login with OTP
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ 
      success: false, 
      error: 'Email and password are required' 
    });
  }

  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user || hashPassword(password) !== user.password) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    const emailSent = await sendEmail({
      to: email,
      subject: 'Your Login OTP Code',
      html: `<h3>Your OTP is: <strong>${otp}</strong></h3><p>Valid for 5 minutes.</p>`
    });

    if (!emailSent) {
      return res.status(500).json({ 
        success: false, 
        error: 'Failed to send OTP email' 
      });
    }

    res.json({ 
      success: true, 
      requiresOtp: true,
      message: 'OTP sent to your email'
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Login failed',
      code: 'LOGIN_ERROR'
    });
  }
});

// Enhanced signup OTP
app.post('/api/auth/signup-otp', async (req, res) => {
  const { email } = req.body;
  if (!validator.isEmail(email)) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please provide a valid email address' 
    });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }

    const otp = generateOTP();
    signupOtpCache.set(email, { 
      otp, 
      expires: Date.now() + 5 * 60 * 1000 // 5 minutes
    });

    const emailSent = await sendEmail({
      to: email,
      subject: 'Verify Your Email for AetherVault',
      html: `<h3>Verification OTP: <strong>${otp}</strong></h3><p>Valid for 5 minutes.</p>`
    });

    if (!emailSent) {
      return res.status(500).json({ 
        success: false, 
        error: 'Failed to send OTP email' 
      });
    }

    res.json({ 
      success: true, 
      message: 'OTP sent to your email',
      expiresIn: '5 minutes'
    });
  } catch (err) {
    console.error('Signup OTP error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send OTP',
      code: 'OTP_ERROR'
    });
  }
});

// Enhanced signup with input validation
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, otp } = req.body;
  
  // Input validation
  if (!name || !email || !password || !otp) {
    return res.status(400).json({ 
      success: false, 
      error: 'All fields are required',
      code: 'MISSING_FIELDS'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      error: 'Password must be at least 8 characters',
      code: 'WEAK_PASSWORD'
    });
  }

  try {
    const cached = signupOtpCache.get(email);
    if (!cached || cached.expires < Date.now()) {
      return res.status(400).json({ 
        success: false, 
        error: 'OTP expired. Please request a new one.',
        code: 'OTP_EXPIRED'
      });
    }

    if (cached.otp !== otp) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid OTP',
        code: 'INVALID_OTP'
      });
    }

    const hashedPass = hashPassword(password);
    const newUser = await User.create({ 
      name, 
      email, 
      password: hashedPass, 
      isVerified: true 
    });

    // Generate tokens
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { 
      expiresIn: '1h' 
    });
    const refreshToken = jwt.sign({ id: newUser._id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: '7d'
    });

    // Clear used OTP
    signupOtpCache.delete(email);

    // Send welcome email
    await sendEmail({
      to: email,
      subject: 'Welcome to AetherVault',
      html: `<h2>Welcome, ${newUser.name}!</h2><p>Your account has been created successfully.</p>`
    });

    res.json({ 
      success: true, 
      token,
      refreshToken,
      user: { 
        id: newUser._id, 
        name: newUser.name, 
        email: newUser.email 
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Registration failed',
      code: 'REGISTRATION_ERROR'
    });
  }
});

// Enhanced OTP verification
app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ 
      success: false, 
      error: 'Email and OTP are required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    const user = await User.findOne({ email }).select('+otp +otpExpires');
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid or expired OTP',
        code: 'INVALID_OTP'
      });
    }

    // Generate tokens
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: '1h' 
    });
    // const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, {
    //   expiresIn: '7d'
    // });

    // Clear OTP
    user.otp = undefined;
    user.otpExpires = undefined;
    user.lastLogin = Date.now();
    await user.save();

    res.json({ 
      success: true, 
      token,
      
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Verification failed',
      code: 'VERIFICATION_ERROR'
    });
  }
});

// Token refresh endpoint
app.post('/api/auth/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ 
      success: false, 
      error: 'Refresh token is required',
      code: 'MISSING_REFRESH_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const newToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: '1h' 
    });

    res.json({ 
      success: true, 
      token: newToken 
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Refresh token expired. Please login again.',
        code: 'REFRESH_TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid refresh token',
      code: 'INVALID_REFRESH_TOKEN'
    });
  }
});

// Enhanced protected routes

// Get user profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -otp -otpExpires');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }
    res.json({ success: true, user });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch profile',
      code: 'PROFILE_ERROR'
    });
  }
});

// List user files
app.get('/api/files/list', verifyToken, async (req, res) => {
  try {
    const files = await File.find({ userId: req.user.id }).sort({ uploadDate: -1 });
    res.json({ success: true, files });
  } catch (err) {
    console.error('File list error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch files',
      code: 'FILE_LIST_ERROR'
    });
  }
});

// File upload with enhanced error handling
app.post('/api/files/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        error: 'No file uploaded',
        code: 'NO_FILE'
      });
    }

    const newFile = await File.create({
      userId: req.user.id,
      originalName: req.file.originalname,
      filename: req.file.filename,
      size: req.file.size,
      mimeType: req.file.mimetype
    });

    res.json({ 
      success: true, 
      file: newFile,
      message: 'File uploaded successfully'
    });
  } catch (err) {
    console.error('Upload error:', err);
    
    // Clean up the uploaded file if database operation failed
    if (req.file) {
      fs.unlink(path.join('uploads', req.file.filename), () => {});
    }

    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        success: false, 
        error: 'File size exceeds 100MB limit',
        code: 'FILE_TOO_LARGE'
      });
    }

    res.status(500).json({ 
      success: false, 
      error: 'File upload failed',
      code: 'UPLOAD_ERROR'
    });
  }
});

// File download endpoint
app.get('/api/files/download/:id', verifyToken, async (req, res) => {
  try {
    const file = await File.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });

    if (!file) {
      return res.status(404).json({ 
        success: false, 
        error: 'File not found',
        code: 'FILE_NOT_FOUND'
      });
    }

    const filePath = path.join('uploads', file.filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ 
        success: false, 
        error: 'File not found on server',
        code: 'FILE_MISSING'
      });
    }

    res.download(filePath, file.originalName);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to download file',
      code: 'DOWNLOAD_ERROR'
    });
  }
});

// File delete endpoint
app.delete('/api/files/delete/:id', verifyToken, async (req, res) => {
  try {
    const file = await File.findOneAndDelete({ 
      _id: req.params.id, 
      userId: req.user.id 
    });

    if (!file) {
      return res.status(404).json({ 
        success: false, 
        error: 'File not found',
        code: 'FILE_NOT_FOUND'
      });
    }

    const filePath = path.join('uploads', file.filename);
    fs.unlink(filePath, (err) => {
      if (err) console.error('Failed to delete file from disk:', err);
    });

    res.json({ 
      success: true, 
      message: 'File deleted successfully' 
    });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete file',
      code: 'DELETE_ERROR'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});