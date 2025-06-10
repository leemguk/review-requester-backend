// src/index.ts - COMPLETE FIXED VERSION
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from './config/environment';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import authRoutes from './routes/auth';
import userRoutes from './routes/user';
import emailRoutes from './routes/email';
import campaignRoutes from './routes/campaigns';
import uploadRoutes from './routes/upload';
import analyticsRoutes from './routes/analytics';
import webhookRoutes from './routes/webhooks';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

app.use(cors({
  origin: ['http://localhost:3000', 'https://nextjs-boilerplate-psi-umber-87.vercel.app'],
  credentials: true
}));

// Trust proxy for rate limiting
app.set('trust proxy', 1);

// Rate limiting (exempt webhooks from rate limiting)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  skip: (req) => req.path.startsWith('/api/webhooks') // Skip rate limiting for webhooks
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static('.'));

// Selective logging middleware - skip webhook spam
app.use((req, res, next) => {
  // Skip logging for webhook endpoints to reduce console noise
  if (!req.path.startsWith('/api/webhooks/')) {
    logger.info(`${req.method} ${req.path} - ${req.ip}`);
  }
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Trustpilot Email SaaS API',
    status: 'running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      test: '/test',
      auth: '/api/auth',
      user: '/api/user',
      email: '/api/email',
      campaigns: '/api/campaigns',
      upload: '/api/upload',
      analytics: '/api/analytics',
      webhooks: '/api/webhooks'
    }
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes); 
app.use('/api/email', emailRoutes);
app.use('/api/campaigns', campaignRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/webhooks', webhookRoutes); // Simple webhook routing

// Test page route
app.get('/test', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>API Test</title></head>
    <body>
      <h1>Test API Endpoints</h1>
      <p>API Base: <code>${req.protocol}://${req.get('host')}</code></p>
      <button onclick="testHealth()">Test Health</button>
      <button onclick="testRegister()">Test Register</button>
      <button onclick="testWebhook()">Test Webhook</button>
      <script>
        async function testHealth() {
          const response = await fetch('/health');
          const result = await response.json();
          alert(JSON.stringify(result, null, 2));
        }

        async function testRegister() {
          const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              email: 'test@example.com',
              password: 'password123',
              firstName: 'Test',
              lastName: 'User'
            })
          });
          const result = await response.json();
          alert(JSON.stringify(result, null, 2));
        }

        async function testWebhook() {
          const response = await fetch('/api/webhooks/sendgrid/test');
          const result = await response.json();
          alert(JSON.stringify(result, null, 2));
        }
      </script>
    </body>
    </html>
  `);
});

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = config.port;
app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
  logger.info(`📧 SendGrid configured: ${!!config.sendgrid.apiKey}`);
  logger.info(`🪝 Webhooks endpoint: /api/webhooks/sendgrid`);
  logger.info(`🌍 Environment: ${config.nodeEnv}`);
});

export default app;