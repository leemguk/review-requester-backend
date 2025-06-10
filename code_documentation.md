# Project Code Documentation
This document contains all the code files in this project.

## package.json
```json
{
  "name": "trustpilot-email-saas",
  "version": "1.0.0",
  "description": "SaaS platform for automated Trustpilot review request emails",
  "main": "dist/index.js",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "db:generate": "prisma generate",
    "db:push": "prisma db push",
    "db:migrate": "prisma migrate dev",
    "db:studio": "prisma studio"
  },
  "dependencies": {
    "@prisma/client": "^4.16.2",
    "@sendgrid/mail": "^8.1.0",
    "@types/pg": "^8.15.4",
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "multer": "^2.0.1",
    "pg": "^8.16.0",
    "winston": "^3.11.0",
    "xlsx": "^0.18.5",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/bcrypt": "^5.0.2",
    "@types/cors": "^2.8.17",
    "@types/express": "^4.17.21",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/node": "^20.10.4",
    "prisma": "^4.16.2",
    "tsx": "^4.6.2",
    "typescript": "^5.3.2"
  }
}

```

## tsconfig.json
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020"],
    "module": "commonjs",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true,
    "allowJs": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## test.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trustpilot Email API Tester</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, textarea, button {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            background: #007cba;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover {
            background: #005a87;
        }
        .response {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin-top: 15px;
            white-space: pre-wrap;
            font-family: monospace;
            max-height: 300px;
            overflow-y: auto;
        }
        .success { border-left: 4px solid #28a745; }
        .error { border-left: 4px solid #dc3545; }
        .step {
            background: #e3f2fd;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        h2 {
            color: #333;
            border-bottom: 2px solid #007cba;
            padding-bottom: 10px;
        }
    </style>
</head>
<body>
    <h1>🚀 Trustpilot Email API Tester</h1>

    <div class="container">
        <div class="step">
            <strong>Step 1:</strong> Update the API Base URL below to match your Replit URL
        </div>
        <div class="form-group">
            <label>API Base URL:</label>
            <input type="text" id="apiUrl" value="https://0ec70d59-1294-41cd-8b60-c4e0f1e13f3a-00-mt1c4uro6nrv.kirk.replit.dev">
        </div>
    </div>

    <!-- User Registration -->
    <div class="container">
        <h2>1. Register User</h2>
        <div class="form-group">
            <label>Email:</label>
            <input type="email" id="regEmail" value="charlie.gilbert@ransomspares.co.uk">
        </div>
        <div class="form-group">
            <label>Password:</label>
            <input type="password" id="regPassword" value="password123">
        </div>
        <div class="form-group">
            <label>First Name:</label>
            <input type="text" id="regFirstName" value="Charlie">
        </div>
        <div class="form-group">
            <label>Last Name:</label>
            <input type="text" id="regLastName" value="Gilbert">
        </div>
        <button onclick="registerUser()">Register User</button>
        <div id="registerResponse" class="response" style="display:none;"></div>
    </div>

    <!-- User Login -->
    <div class="container">
        <h2>2. Login User</h2>
        <div class="form-group">
            <label>Email:</label>
            <input type="email" id="loginEmail" value="charlie.gilbert@ransomspares.co.uk">
        </div>
        <div class="form-group">
            <label>Password:</label>
            <input type="password" id="loginPassword" value="password123">
        </div>
        <button onclick="loginUser()">Login</button>
        <div id="loginResponse" class="response" style="display:none;"></div>
    </div>

    <!-- Email Sending -->
    <div class="container">
        <h2>3. Send Review Request Emails</h2>
        <div class="step">
            <strong>Note:</strong> You need to login first to get a token!
        </div>
        <div class="form-group">
            <label>Auth Token (from login):</label>
            <input type="text" id="authToken" placeholder="Paste token from login response">
        </div>
        <div class="form-group">
            <label>Template ID:</label>
            <input type="number" id="templateId" value="1">
        </div>
        <div class="form-group">
            <label>Customer Data (JSON):</label>
            <textarea id="customerData" rows="8">[
  {
    "name": "Test Customer",
    "email": "test@example.com"
  },
  {
    "name": "John Doe", 
    "email": "john@example.com"
  }
]</textarea>
        </div>
        <button onclick="sendEmails()">Send Emails</button>
        <div id="emailResponse" class="response" style="display:none;"></div>
    </div>

    <script>
        let currentToken = '';

        async function makeRequest(endpoint, method = 'GET', data = null, useAuth = false) {
            const apiUrl = document.getElementById('apiUrl').value;
            const url = `${apiUrl}${endpoint}`;

            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                }
            };

            if (useAuth && currentToken) {
                options.headers['Authorization'] = `Bearer ${currentToken}`;
            }

            if (data) {
                options.body = JSON.stringify(data);
            }

            try {
                const response = await fetch(url, options);
                const result = await response.json();
                return { status: response.status, data: result };
            } catch (error) {
                return { status: 0, data: { error: error.message } };
            }
        }

        function displayResponse(elementId, response, isSuccess) {
            const element = document.getElementById(elementId);
            element.style.display = 'block';
            element.textContent = JSON.stringify(response.data, null, 2);
            element.className = `response ${isSuccess ? 'success' : 'error'}`;
        }

        async function registerUser() {
            const data = {
                email: document.getElementById('regEmail').value,
                password: document.getElementById('regPassword').value,
                firstName: document.getElementById('regFirstName').value,
                lastName: document.getElementById('regLastName').value
            };

            const response = await makeRequest('/api/auth/register', 'POST', data);
            const isSuccess = response.status === 201;
            displayResponse('registerResponse', response, isSuccess);

            if (isSuccess && response.data.data && response.data.data.token) {
                currentToken = response.data.data.token;
                document.getElementById('authToken').value = currentToken;
                alert('✅ Registration successful! Token saved automatically.');
            }
        }

        async function loginUser() {
            const data = {
                email: document.getElementById('loginEmail').value,
                password: document.getElementById('loginPassword').value
            };

            const response = await makeRequest('/api/auth/login', 'POST', data);
            const isSuccess = response.status === 200;
            displayResponse('loginResponse', response, isSuccess);

            if (isSuccess && response.data.data && response.data.data.token) {
                currentToken = response.data.data.token;
                document.getElementById('authToken').value = currentToken;
                alert('✅ Login successful! Token saved automatically.');
            }
        }

        async function sendEmails() {
            const token = document.getElementById('authToken').value;
            if (!token) {
                alert('❌ Please login first to get an auth token!');
                return;
            }

            let customers;
            try {
                customers = JSON.parse(document.getElementById('customerData').value);
            } catch (error) {
                alert('❌ Invalid JSON in customer data!');
                return;
            }

            const data = {
                customers: customers,
                templateId: parseInt(document.getElementById('templateId').value),
                campaignName: `Test Campaign ${new Date().toISOString()}`
            };

            // Temporarily set token for this request
            const originalToken = currentToken;
            currentToken = token;

            const response = await makeRequest('/api/email/send', 'POST', data, true);
            const isSuccess = response.status === 200;
            displayResponse('emailResponse', response, isSuccess);

            currentToken = originalToken;

            if (isSuccess) {
                alert('✅ Emails sent successfully! Check the response for details.');
            }
        }
    </script>
</body>
</html>
```

## generate_docs.py
```python
import os
import fnmatch

def should_ignore_file(filepath, ignore_patterns):
    """Check if file should be ignored based on patterns"""
    filename = os.path.basename(filepath)
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filepath, pattern):
            return True
    return False

def get_language_from_extension(filepath):
    """Get language identifier for markdown code blocks based on file extension"""
    ext_to_lang = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.jsx': 'javascript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.sh': 'bash',
        '.sql': 'sql',
        '.json': 'json',
        '.xml': 'xml',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.md': 'markdown',
        '.txt': 'text'
    }

    _, ext = os.path.splitext(filepath.lower())
    return ext_to_lang.get(ext, 'text')

def generate_code_documentation(root_dir='.', markdown_file='code_documentation.md', text_file='code_documentation.txt'):
    """Generate both markdown and plain text documentation of all code files in the project"""

    # Common files/patterns to ignore
    ignore_patterns = [
        '*.pyc', '__pycache__', '.git', '.gitignore', 
        'node_modules', '.env', '*.log', '.DS_Store',
        '*.min.js', '*.min.css', 'package-lock.json',
        'yarn.lock', '.replit', 'replit.nix', '*.md'
    ]

    # Common code file extensions
    code_extensions = {
        '.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.css', '.java', 
        '.cpp', '.c', '.cs', '.php', '.rb', '.go', 
        '.rs', '.sh', '.sql', '.json', '.xml', '.yml', '.yaml'
    }

    markdown_content = []
    text_content = []

    # Headers for both formats
    markdown_content.append("# Project Code Documentation\n")
    markdown_content.append("This document contains all the code files in this project.\n")

    text_content.append("PROJECT CODE DOCUMENTATION\n")
    text_content.append("=" * 50 + "\n")
    text_content.append("This document contains all the code files in this project.\n\n")

    file_count = 0

    # Walk through all files in the project
    for root, dirs, files in os.walk(root_dir):
        print(f"Scanning directory: {root}")
        # Skip hidden directories and common ignore directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]

        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, root_dir)

            # Skip if file should be ignored
            if should_ignore_file(relative_path, ignore_patterns):
                continue

            # Only include files with code extensions
            _, ext = os.path.splitext(file.lower())
            if ext not in code_extensions:
                continue

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Add to markdown format
                markdown_content.append(f"\n## {relative_path}\n")
                language = get_language_from_extension(filepath)
                markdown_content.append(f"```{language}\n{content}\n```\n")

                # Add to plain text format
                text_content.append(f"\n{'='*60}\n")
                text_content.append(f"FILE: {relative_path}\n")
                text_content.append(f"{'='*60}\n\n")
                text_content.append(content)
                text_content.append("\n\n")

                file_count += 1
                print(f"Added: {relative_path}")

            except (UnicodeDecodeError, PermissionError) as e:
                print(f"Skipped {relative_path}: {e}")
                continue

    # Write both files
    try:
        # Write markdown file
        with open(markdown_file, 'w', encoding='utf-8') as f:
            f.write(''.join(markdown_content))
        print(f"\nMarkdown documentation generated: {markdown_file}")

        # Write plain text file
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(''.join(text_content))
        print(f"Plain text documentation generated: {text_file}")

        print(f"Total files processed: {file_count}")

    except Exception as e:
        print(f"Error writing output files: {e}")

if __name__ == "__main__":
    # You can customize these parameters
    ROOT_DIRECTORY = '.'  # Current directory (the Replit project root)
    MARKDOWN_FILE = 'code_documentation.md'
    TEXT_FILE = 'code_documentation.txt'

    generate_code_documentation(ROOT_DIRECTORY, MARKDOWN_FILE, TEXT_FILE)
```

## src/index.ts
```typescript
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
```

## src/config/environment.ts
```typescript
// src/config/environment.ts
import dotenv from 'dotenv';

dotenv.config();

const required = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
};

const optional = (key: string, defaultValue: string = ''): string => {
  return process.env[key] || defaultValue;
};

export const config = {
  nodeEnv: optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '3000')),

  // Database
  database: {
    url: required('DATABASE_URL'),
  },

  // SendGrid
  sendgrid: {
    apiKey: required('SENDGRID_API_KEY'),
  },

  // JWT
  jwt: {
    secret: required('JWT_SECRET'),
    expiresIn: optional('JWT_EXPIRES_IN', '7d'),
  },

  // Frontend
  frontend: {
    url: optional('FRONTEND_URL', 'http://localhost:3000'),
  },

  // Redis (for caching/sessions)
  redis: {
    url: optional('REDIS_URL', 'redis://localhost:6379'),
  },

  // App settings
  app: {
    name: optional('APP_NAME', 'Trustpilot Email Agent'),
    supportEmail: optional('SUPPORT_EMAIL', 'support@yourdomain.com'),
  }
};

// Validate critical config on startup
const validateConfig = () => {
  try {
    required('DATABASE_URL');
    required('SENDGRID_API_KEY');
    required('JWT_SECRET');
    console.log('✅ Configuration validated successfully');
  } catch (error) {
    console.error('❌ Configuration validation failed:', error);
    process.exit(1);
  }
};

validateConfig();
```

## src/middleware/auth.ts
```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/environment';
import { logger } from '../utils/logger';

export interface AuthenticatedRequest extends Request {
  user: {
    id: number;
    email: string;
  };
}

export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  try {
    const decoded = jwt.verify(token, config.jwt.secret) as {
      id: number;
      email: string;
    };

    (req as AuthenticatedRequest).user = decoded;
    next();
  } catch (error) {
    logger.warn(`Invalid token attempt: ${error}`);
    return res.status(403).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }
};
```

## src/middleware/validation.ts
```typescript
import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

export const validateRequest = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse({
        body: req.body,
        query: req.query,
        params: req.params
      });
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));

        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors
        });
      }

      return res.status(500).json({
        success: false,
        error: 'Internal validation error'
      });
    }
  };
};
```

## src/middleware/errorHandler.ts
```typescript
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { statusCode = 500, message, stack } = err;

  logger.error('Error occurred:', {
    error: message,
    statusCode,
    stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't leak error details in production
  const errorMessage = process.env.NODE_ENV === 'production' 
    ? 'Something went wrong' 
    : message;

  res.status(statusCode).json({
    success: false,
    error: errorMessage,
    ...(process.env.NODE_ENV === 'development' && { stack })
  });
};
```

## src/routes/auth.ts
```typescript
import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { config } from '../config/environment';
import { validateRequest } from '../middleware/validation';
import { logger } from '../utils/logger';
import { z } from 'zod';

const router = Router();

// Validation schemas
const registerSchema = z.object({
  body: z.object({
    email: z.string().email('Valid email is required'),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    firstName: z.string().min(1, 'First name is required'),
    lastName: z.string().min(1, 'Last name is required')
  })
});

const loginSchema = z.object({
  body: z.object({
    email: z.string().email('Valid email is required'),
    password: z.string().min(1, 'Password is required')
  })
});

// POST /api/auth/register
router.post('/register', 
  validateRequest(registerSchema),
  async (req: Request, res: Response) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      // TODO: Check if user already exists in database
      // const existingUser = await db.user.findUnique({ where: { email } });
      // if (existingUser) {
      //   return res.status(400).json({
      //     success: false,
      //     error: 'User with this email already exists'
      //   });
      // }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // TODO: Create user in database
      const user = {
        id: Date.now(), // Temporary ID
        email: email.toLowerCase(),
        firstName,
        lastName,
        password: hashedPassword,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, email: user.email },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );

      logger.info(`New user registered: ${email}`);

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName
          },
          token
        },
        message: 'User registered successfully'
      });

    } catch (error) {
      logger.error('Error in user registration:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to register user'
      });
    }
  }
);

// POST /api/auth/login
router.post('/login',
  validateRequest(loginSchema),
  async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      // TODO: Get user from database
      // const user = await db.user.findUnique({ 
      //   where: { email: email.toLowerCase() } 
      // });

      // Mock user for now
      const user = {
        id: 1,
        email: 'charlie.gilbert@ransomspares.co.uk',
        password: await bcrypt.hash('password123', 12), // Mock hashed password
        firstName: 'Charlie',
        lastName: 'Gilbert',
        isActive: true
      };

      if (!user || !user.isActive) {
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password'
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password'
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, email: user.email },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );

      logger.info(`User logged in: ${email}`);

      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName
          },
          token
        },
        message: 'Login successful'
      });

    } catch (error) {
      logger.error('Error in user login:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to login'
      });
    }
  }
);

// POST /api/auth/logout
router.post('/logout', (req: Request, res: Response) => {
  // TODO: Invalidate token in database/Redis
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

export default router;
```

## src/routes/campaigns.ts
```typescript
import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { logger } from '../utils/logger';
import { z } from 'zod';

const router = Router();

// GET /api/campaigns - Get all campaigns for user's companies
router.get('/', 
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      // TODO: Get campaigns from database
      const campaigns = [
        {
          id: 1,
          name: 'Q1 Review Campaign',
          status: 'SENT',
          totalEmails: 150,
          sentEmails: 148,
          failedEmails: 2,
          sentAt: new Date('2024-03-15'),
          createdAt: new Date('2024-03-14'),
          template: {
            name: 'Default Review Request'
          }
        }
      ];

      res.json({
        success: true,
        data: campaigns
      });

    } catch (error) {
      logger.error('Error fetching campaigns:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch campaigns'
      });
    }
  }
);

// GET /api/campaigns/:id - Get specific campaign details
router.get('/:id',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const campaignId = parseInt(req.params.id);

      // TODO: Get campaign from database with email logs
      const campaign = {
        id: campaignId,
        name: 'Q1 Review Campaign',
        status: 'SENT',
        totalEmails: 150,
        sentEmails: 148,
        failedEmails: 2,
        sentAt: new Date('2024-03-15'),
        createdAt: new Date('2024-03-14'),
        emailLogs: [
          {
            customerEmail: 'customer@example.com',
            customerName: 'John Doe',
            status: 'DELIVERED',
            sentAt: new Date('2024-03-15T10:00:00Z'),
            openedAt: new Date('2024-03-15T11:30:00Z')
          }
        ]
      };

      res.json({
        success: true,
        data: campaign
      });

    } catch (error) {
      logger.error('Error fetching campaign:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch campaign'
      });
    }
  }
);

// DELETE /api/campaigns/:id - Delete a campaign
router.delete('/:id',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const campaignId = parseInt(req.params.id);

      // TODO: Delete campaign from database
      // await db.campaign.delete({ where: { id: campaignId } });

      res.json({
        success: true,
        message: 'Campaign deleted successfully'
      });

    } catch (error) {
      logger.error('Error deleting campaign:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to delete campaign'
      });
    }
  }
);

export default router
```

## src/routes/analytics.ts
```typescript
// src/routes/analytics.ts - CLEANED VERSION WITH REDUCED LOGGING
import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';
import { db } from '../lib/prisma';

const router = Router();

// GET /api/analytics/stats - Return real analytics data
router.get('/stats',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user.id;
      const timeRange = req.query.timeRange as string || '30d';

      // Calculate date filter based on time range
      let dateFilter = '';
      switch (timeRange) {
        case '7d':
          dateFilter = `AND "createdAt" >= NOW() - INTERVAL '7 days'`;
          break;
        case '30d':
          dateFilter = `AND "createdAt" >= NOW() - INTERVAL '30 days'`;
          break;
        case '90d':
          dateFilter = `AND "createdAt" >= NOW() - INTERVAL '90 days'`;
          break;
        default:
          dateFilter = `AND "createdAt" >= NOW() - INTERVAL '30 days'`;
      }

      // Get total emails sent in time period
      const emailsResult = await db.query(`
        SELECT COUNT(*) as count 
        FROM emails 
        WHERE "userId" = $1 ${dateFilter}
      `, [userId.toString()]);

      // Get email status breakdown
      const statusResult = await db.query(`
        SELECT 
          status,
          COUNT(*) as count
        FROM emails 
        WHERE "userId" = $1 ${dateFilter}
        GROUP BY status
      `, [userId.toString()]);

      // Get monthly usage (current month)
      const monthlyResult = await db.query(`
        SELECT COUNT(*) as count 
        FROM emails 
        WHERE "userId" = $1 
        AND "createdAt" >= DATE_TRUNC('month', NOW())
      `, [userId.toString()]);

      // Process the results
      const totalEmails = parseInt(emailsResult.rows[0]?.count || '0');
      const monthlyEmails = parseInt(monthlyResult.rows[0]?.count || '0');

      // Create status breakdown
      const statusBreakdown: Record<string, number> = {};
      statusResult.rows.forEach(row => {
        statusBreakdown[row.status] = parseInt(row.count);
      });

      // Calculate stats
      const emailsSent = totalEmails;
      const delivered = statusBreakdown['sent'] || 0;
      const opened = statusBreakdown['opened'] || 0;
      const clicked = statusBreakdown['clicked'] || 0;
      const bounced = statusBreakdown['bounced'] || 0;
      const spam = statusBreakdown['spam'] || 0;
      const failed = statusBreakdown['failed'] || 0;

      // Calculate rates (avoid division by zero)
      const deliveryRate = emailsSent > 0 ? Math.round((delivered / emailsSent) * 100) : 0;
      const openRate = delivered > 0 ? Math.round((opened / delivered) * 100) : 0;
      const clickRate = opened > 0 ? Math.round((clicked / opened) * 100) : 0;
      const bounceRate = emailsSent > 0 ? Math.round((bounced / emailsSent) * 100) : 0;
      const spamRate = emailsSent > 0 ? Math.round((spam / emailsSent) * 100) : 0;

      // Monthly limits
      const monthlyLimit = 1000;
      const usagePercentage = monthlyLimit > 0 ? Math.round((monthlyEmails / monthlyLimit) * 100) : 0;

      const analyticsData = {
        totalUsers: 1,
        totalCampaigns: 0,
        totalEmails: emailsSent,
        recentActivity: emailsSent,
        emailsSent,
        emailsDelivered: delivered,
        emailsOpened: opened,
        emailsClicked: clicked,
        deliveryRate,
        openRate,
        clickRate,
        bounceRate,
        spamRate,
        monthlyEmails,
        monthlyLimit,
        usagePercentage,
        delivered,
        opened,
        clicked,
        bounced,
        spam,
        failed,
        emailStats: {
          sent: emailsSent,
          delivered,
          opened,
          clicked,
          bounced,
          spam,
          failed
        }
      };

      res.json({
        success: true,
        data: analyticsData
      });

    } catch (error) {
      logger.error('Analytics stats error:', error);

      // Return default values instead of erroring
      res.json({
        success: true,
        data: {
          totalUsers: 1,
          totalCampaigns: 0,
          totalEmails: 0,
          recentActivity: 0,
          emailsSent: 0,
          emailsDelivered: 0,
          emailsOpened: 0,
          emailsClicked: 0,
          deliveryRate: 0,
          openRate: 0,
          clickRate: 0,
          bounceRate: 0,
          spamRate: 0,
          delivered: 0,
          opened: 0,
          clicked: 0,
          bounced: 0,
          spam: 0,
          failed: 0,
          monthlyEmails: 0,
          monthlyLimit: 1000,
          usagePercentage: 0,
          emailStats: {
            sent: 0,
            delivered: 0,
            opened: 0,
            clicked: 0,
            bounced: 0,
            spam: 0,
            failed: 0
          }
        }
      });
    }
  }
);

// GET /api/analytics/activity - Get recent email activity (CLEANED)
router.get('/activity',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user.id;
      const limit = parseInt(req.query.limit as string) || 6;

      const activityResult = await db.query(`
        SELECT 
          id,
          "to" as customer_email,
          subject,
          status,
          "createdAt"
        FROM emails 
        WHERE "userId" = $1 
        ORDER BY "createdAt" DESC 
        LIMIT $2
      `, [userId.toString(), limit]);

      // Transform the data to match frontend expectations
      const activityArray = activityResult.rows.map(row => {
        const now = new Date();
        const created = new Date(row.createdAt);
        const diffMs = now.getTime() - created.getTime();
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffHours / 24);

        let timeAgo;
        if (diffDays > 0) {
          timeAgo = `${diffDays}d ago`;
        } else if (diffHours > 0) {
          timeAgo = `${diffHours}h ago`;
        } else if (diffMinutes > 0) {
          timeAgo = `${diffMinutes}m ago`;
        } else {
          timeAgo = 'Just now';
        }

        // Extract customer name from subject
        let customerName = 'Customer';
        if (row.subject && row.subject.includes('for ')) {
          const nameMatch = row.subject.match(/for (.+)$/);
          if (nameMatch) {
            customerName = nameMatch[1];
          }
        }

        return {
          id: row.id,
          customerName: customerName,
          customerEmail: row.customer_email,
          status: 'delivered',
          timestamp: row.createdAt,
          timeAgo: timeAgo,
          platform: 'Trustpilot'
        };
      });

      res.json({
        success: true,
        data: activityArray
      });

    } catch (error) {
      logger.error('Activity fetch error:', error);
      res.json({
        success: true,
        data: []
      });
    }
  }
);

// GET /api/analytics/dashboard - Get dashboard summary
router.get('/dashboard',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user.id;

      const [emailsToday, emailsThisWeek, emailsThisMonth] = await Promise.all([
        db.query(`
          SELECT COUNT(*) as count 
          FROM emails 
          WHERE "userId" = $1 
          AND DATE("createdAt") = CURRENT_DATE
        `, [userId.toString()]),

        db.query(`
          SELECT COUNT(*) as count 
          FROM emails 
          WHERE "userId" = $1 
          AND "createdAt" >= DATE_TRUNC('week', NOW())
        `, [userId.toString()]),

        db.query(`
          SELECT COUNT(*) as count 
          FROM emails 
          WHERE "userId" = $1 
          AND "createdAt" >= DATE_TRUNC('month', NOW())
        `, [userId.toString()])
      ]);

      const dashboard = {
        emailsToday: parseInt(emailsToday.rows[0]?.count || '0'),
        emailsThisWeek: parseInt(emailsThisWeek.rows[0]?.count || '0'),
        emailsThisMonth: parseInt(emailsThisMonth.rows[0]?.count || '0'),
        timestamp: new Date().toISOString()
      };

      res.json({
        success: true,
        data: dashboard
      });

    } catch (error) {
      logger.error('Dashboard fetch error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch dashboard data'
      });
    }
  }
);

export default router;
```

## src/routes/user.ts
```typescript
// src/routes/user.ts - NEW FILE
import { Router, Request, Response } from 'express';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { logger } from '../utils/logger';
import { db } from '../lib/prisma';
import { z } from 'zod';

const router = Router();

// Validation schemas
const updateEmailSettingsSchema = z.object({
  body: z.object({
    displayName: z.string().min(1, 'Display name is required').max(50, 'Display name too long')
  })
});

// GET /api/user/email-settings - Get user's email settings
router.get('/email-settings', 
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as AuthenticatedRequest).user.id;

      // Try to get from database
      try {
        const result = await db.query(`
          SELECT display_name, from_email 
          FROM user_email_settings 
          WHERE user_id = $1
        `, [userId.toString()]);

        if (result.rows.length > 0) {
          const settings = result.rows[0];
          res.json({
            success: true,
            data: {
              displayName: settings.display_name,
              fromEmail: settings.from_email || 'charlie.gilbert@ransomspares.co.uk'
            }
          });
        } else {
          // Return defaults if no settings exist
          res.json({
            success: true,
            data: {
              displayName: '',
              fromEmail: 'charlie.gilbert@ransomspares.co.uk'
            }
          });
        }
      } catch (dbError) {
        // If table doesn't exist, return defaults
        logger.warn('user_email_settings table not found, returning defaults');
        res.json({
          success: true,
          data: {
            displayName: '',
            fromEmail: 'charlie.gilbert@ransomspares.co.uk'
          }
        });
      }

    } catch (error) {
      logger.error('Error fetching email settings:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch email settings'
      });
    }
  }
);

// PUT /api/user/email-settings - Update user's email settings
router.put('/email-settings',
  authenticateToken,
  validateRequest(updateEmailSettingsSchema),
  async (req: Request, res: Response) => {
    try {
      const userId = (req as AuthenticatedRequest).user.id;
      const { displayName } = req.body;

      // Create table if it doesn't exist
      await db.query(`
        CREATE TABLE IF NOT EXISTS user_email_settings (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) UNIQUE NOT NULL,
          display_name VARCHAR(255) NOT NULL,
          from_email VARCHAR(255) DEFAULT 'charlie.gilbert@ransomspares.co.uk',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);

      // Upsert the settings
      await db.query(`
        INSERT INTO user_email_settings (user_id, display_name, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (user_id) 
        DO UPDATE SET 
          display_name = EXCLUDED.display_name,
          updated_at = NOW()
      `, [userId.toString(), displayName]);

      res.json({
        success: true,
        data: {
          displayName,
          fromEmail: 'charlie.gilbert@ransomspares.co.uk'
        },
        message: 'Email settings updated successfully'
      });

    } catch (error) {
      logger.error('Error updating email settings:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to update email settings'
      });
    }
  }
);

export default router;
```

## src/routes/email.ts
```typescript
// src/routes/email.ts - UPDATED VERSION WITH DATABASE EMAIL SETTINGS
import { Router, Request, Response } from 'express';
import { EmailService } from '../services/emailService';
import { authenticateToken } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { ApiResponse, SendEmailRequest } from '../types/database';
import { logger } from '../utils/logger';
import { db } from '../lib/prisma';
import { z } from 'zod';

const router = Router();

// Validation schemas
const sendEmailSchema = z.object({
  body: z.object({
    customers: z.array(z.object({
      name: z.string().min(1, 'Name is required'),
      email: z.string().email('Valid email is required'),
      customFields: z.record(z.string()).optional()
    })).min(1, 'At least one customer is required'),
    templateId: z.number().int().positive('Valid template ID is required'),
    campaignName: z.string().optional(),
    scheduledAt: z.string().datetime().optional()
  })
});

// Helper function to get user's email settings
async function getUserEmailSettings(userId: string) {
  try {
    const result = await db.query(`
      SELECT display_name, from_email 
      FROM user_email_settings 
      WHERE user_id = $1
    `, [userId]);

    if (result.rows.length > 0) {
      return {
        displayName: result.rows[0].display_name,
        fromEmail: result.rows[0].from_email || 'charlie.gilbert@ransomspares.co.uk'
      };
    }

    // Return defaults if no settings found
    return {
      displayName: 'Review Team',
      fromEmail: 'charlie.gilbert@ransomspares.co.uk'
    };
  } catch (error) {
    logger.warn('Could not fetch user email settings, using defaults:', error);
    return {
      displayName: 'Review Team',
      fromEmail: 'charlie.gilbert@ransomspares.co.uk'
    };
  }
}

// POST /api/email/send - Send review request emails
router.post('/send', 
  authenticateToken,
  validateRequest(sendEmailSchema),
  async (req: Request, res: Response) => {
    try {
      const { customers, templateId, campaignName }: SendEmailRequest = req.body;
      const authenticatedUser = (req as any).user;
      const userId = authenticatedUser.id; // Extract user ID from JWT token

      // Validate customers
      const { valid: validCustomers, invalid: invalidCustomers } = 
        EmailService.validateCustomers(customers);

      if (validCustomers.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'No valid customers provided',
          data: { invalidCustomers }
        } as ApiResponse);
      }

      // Fetch user's email settings from database
      const userEmailSettings = await getUserEmailSettings(userId.toString());

      logger.info(`Using email settings for user ${userId}:`, {
        displayName: userEmailSettings.displayName,
        fromEmail: userEmailSettings.fromEmail
      });

      // TODO: Get company and template from database based on user
      // For now, we'll use mock data but with the user's actual email settings
      const company = {
        id: 1,
        name: 'Ransom Spares.co.uk Ltd',
        trustpilotUrl: 'https://uk.trustpilot.com/evaluate/ransomspares.co.uk',
        fromEmail: userEmailSettings.fromEmail,
        fromName: userEmailSettings.displayName // Use the user's display name from database
      };

      // src/routes/email.ts - Update the template section

      // Personal email template - replace in src/routes/email.ts

      const template = {
        id: templateId,
        name: 'Default Review Request',
        platform: 'TRUSTPILOT',
        subject: `We'd love your feedback, {{customerName}}!`,
        html: `<!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 20px; font-size: 14px;">

        <div style="max-width: 600px; margin: 0 auto;">

          <p>Hello {{customerName}},</p>

          <p>I hope this email finds you well. I'm reaching out to thank you for choosing us for your recent order, it really means a lot.</p>

          <p>As a family-run business based in Somerset, we take great pride in providing fast, reliable, and personalised service to each of our customers. We believe in what we do and are always striving to improve and grow.</p>

          <p>To help us spread the word and grow our customer base, we'd be incredibly grateful if you could leave us a review on Trustpilot. Your feedback will not only help us grow, but also allow others to see the level of service we provide.</p>

          <p>To leave your feedback, just <a href="{{trustpilotLink}}" style="color: #0066cc;">review us on Trustpilot</a>.</p>

          <p>We truly appreciate your support and look forward to continuing to serve you in the future.</p>

          <p>Thank you again for your trust in us.</p>

          <p>Best regards,<br/>
          {{fromName}}<br/>
          {{companyName}}<br/>
          E: {{fromEmail}}</p>

          <hr style="border: none; border-top: 1px solid #cccccc; margin: 30px 0;">

          <div style="font-size: 11px; color: #666666; line-height: 1.4;">
            <p>{{companyName}}<br/>
            Supplier of spares and accessories for electric domestic appliances.</p>

            <p>The information in this email and attachments is confidential and intended for the sole use of the addressee(s). Access, copying, disclosure or re-use, in any way, of the information contained in this email and attachments by anyone other than the addressee(s) are unauthorised. If you have received this email in error, please return it to the sender and highlight the error. We accept no legal liability for the content of the message. Any opinions or views presented are solely the responsibility of the author and do not necessarily represent those of {{companyName}}. We cannot guarantee that this message has not been modified in transit, and this message should not be viewed as contractually binding. Although we have taken reasonable steps to ensure that this email and attachments are free from any virus, we advise that in keeping with good computing practice the recipient should ensure they are actually virus free.</p>

            <p>Without prejudice and subject to contract. Company Reg: 6779183. VAT Number: 948195871</p>
          </div>

        </div>

      </body>
      </html>`
      };

      const reviewPlatform = {
        id: 1,
        platform: 'TRUSTPILOT',
        name: 'Our Trustpilot Page',
        reviewUrl: 'https://uk.trustpilot.com/evaluate/ransomspares.co.uk',
        isActive: true,
        isDefault: true
      };

      // TODO: Check subscription limits based on user
      // const subscription = await getSubscription(userId);
      // if (subscription.emailsUsed + validCustomers.length > subscription.emailsPerMonth) {
      //   return res.status(403).json({
      //     success: false,
      //     error: 'Email limit exceeded for current subscription'
      //   });
      // }

      const emailService = new EmailService();
      const results = await emailService.sendReviewRequestEmails(
        validCustomers,
        company as any,
        template as any,
        reviewPlatform as any,
        userId // Pass the authenticated user's ID
      );

      const successCount = results.filter(r => r.success).length;
      const failureCount = results.filter(r => !r.success).length;

      // TODO: Create campaign record in database
      // const campaign = await createCampaign({
      //   name: campaignName || `Campaign ${new Date().toISOString()}`,
      //   userId: userId,
      //   templateId: template.id,
      //   customers: validCustomers,
      //   totalEmails: validCustomers.length,
      //   sentEmails: successCount,
      //   failedEmails: failureCount
      // });

      res.json({
        success: true,
        message: `✅ ${successCount} emails sent successfully${failureCount ? `, ${failureCount} failed` : ''}`,
        data: {
          sent: successCount,
          failed: failureCount,
          invalidCustomers: invalidCustomers.length,
          userId: userId, // Include user ID in response for debugging
          fromName: userEmailSettings.displayName, // Include fromName for confirmation
          results: results.map(r => ({
            customerEmail: r.customer.email,
            success: r.success,
            error: r.error
          }))
        }
      } as ApiResponse);

    } catch (error) {
      logger.error('Error in email send endpoint:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId: (req as any).user?.id
      });

      res.status(500).json({
        success: false,
        error: 'Failed to send emails',
        message: error instanceof Error ? error.message : 'Unknown error'
      } as ApiResponse);
    }
  }
);

// GET /api/email/templates - Get email templates for company
router.get('/templates', 
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user.id;

      // TODO: Get templates from database filtered by user/company
      const templates = [
        {
          id: 1,
          name: 'Default Review Request',
          subject: `We'd love your feedback, {{customerName}}!`,
          platform: 'TRUSTPILOT',
          isDefault: true,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ];

      res.json({
        success: true,
        data: templates
      } as ApiResponse);

    } catch (error) {
      logger.error('Error fetching templates:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch templates'
      } as ApiResponse);
    }
  }
);

// POST /api/email/templates - Create new email template
router.post('/templates',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const { name, subject, html, platform, isDefault } = req.body;
      const userId = (req as any).user.id;

      // TODO: Validate and create template in database
      const template = {
        id: Date.now(), // Temporary ID
        name,
        subject,
        html,
        platform: platform || 'TRUSTPILOT',
        isDefault: isDefault || false,
        isActive: true,
        userId: userId, // Associate with authenticated user
        createdAt: new Date(),
        updatedAt: new Date()
      };

      res.status(201).json({
        success: true,
        data: template,
        message: 'Template created successfully'
      } as ApiResponse);

    } catch (error) {
      logger.error('Error creating template:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to create template'
      } as ApiResponse);
    }
  }
);

// GET /api/email/history - Get email sending history for user
router.get('/history',
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user.id;
      const limit = parseInt(req.query.limit as string) || 50;
      const offset = parseInt(req.query.offset as string) || 0;

      // This endpoint can be implemented later when you want to show email history
      res.json({
        success: true,
        data: {
          emails: [],
          total: 0,
          limit,
          offset
        },
        message: 'Email history endpoint - to be implemented'
      } as ApiResponse);

    } catch (error) {
      logger.error('Error fetching email history:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch email history'
      } as ApiResponse);
    }
  }
);

export default router;
```

## src/routes/webhooks.ts
```typescript
// In src/routes/webhooks.ts - Replace with minimal logging version:

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { db } from '../lib/prisma';

const router = Router();

// Track basic stats without spam
let webhookStats = {
  totalProcessed: 0,
  totalSkipped: 0,
  lastReset: new Date()
};

// POST /api/webhooks/sendgrid - Clean version with minimal logging
router.post('/sendgrid', async (req: Request, res: Response) => {
  try {
    const events = Array.isArray(req.body) ? req.body : [req.body];
    let processedCount = 0;
    let skippedCount = 0;

    for (const event of events) {
      try {
        const result = await processSendGridEvent(event);
        if (result === 'processed') {
          processedCount++;
          webhookStats.totalProcessed++;
        } else {
          skippedCount++;
          webhookStats.totalSkipped++;
        }
      } catch (error) {
        // Silent error handling - only log actual errors
        logger.error('Webhook event processing error:', error);
      }
    }

    // Only log if we processed review app emails (skip e-commerce noise)
    if (processedCount > 0) {
      logger.info(`📧 Processed ${processedCount} review app events`);
    }

    res.status(200).json({ 
      processed: processedCount,
      skipped: skippedCount
    });

  } catch (error) {
    logger.error('Webhook batch error:', error);
    res.status(200).json({ error: 'Processing failed' });
  }
});

// Clean event processing - no spam logging
async function processSendGridEvent(event: any): Promise<'processed' | 'skipped'> {
  try {
    const customerEmail = event.email;
    const eventType = event.event;
    const timestamp = event.timestamp ? new Date(event.timestamp * 1000) : new Date();

    if (!customerEmail || !eventType) {
      return 'skipped';
    }

    // Check if email exists in our review app database
    const emailResult = await db.query(`
      SELECT id, "userId", "to", status, "createdAt"
      FROM emails 
      WHERE "to" = $1
      ORDER BY "createdAt" DESC
      LIMIT 1
    `, [customerEmail]);

    const emailRecord = emailResult.rows[0];

    if (!emailRecord) {
      return 'skipped'; // E-commerce email, skip silently
    }

    // Update email status
    const success = await updateEmailStatus(emailRecord.id, eventType, timestamp, customerEmail);

    // Only log important events, not every single one
    if (success && ['open', 'click', 'bounce', 'spamreport'].includes(eventType)) {
      logger.info(`📧 ${eventType.toUpperCase()}: ${customerEmail}`);
    }

    return 'processed';

  } catch (error) {
    throw error;
  }
}

// Clean email status update - no verbose logging
async function updateEmailStatus(
  emailId: string, 
  eventType: string, 
  timestamp: Date,
  customerEmail: string
): Promise<boolean> {
  try {
    let updateQuery = '';
    let updateParams: any[] = [];

    switch (eventType) {
      case 'delivered':
        updateQuery = `UPDATE emails SET status = $1, "deliveredAt" = $3, "updatedAt" = NOW() WHERE id = $2`;
        updateParams = ['delivered', emailId, timestamp];
        break;
      case 'open':
        updateQuery = `UPDATE emails SET status = $1, "openedAt" = $3, "openCount" = COALESCE("openCount", 0) + 1, "updatedAt" = NOW() WHERE id = $2`;
        updateParams = ['opened', emailId, timestamp];
        break;
      case 'click':
        updateQuery = `UPDATE emails SET status = $1, "clickedAt" = $3, "clickCount" = COALESCE("clickCount", 0) + 1, "updatedAt" = NOW() WHERE id = $2`;
        updateParams = ['clicked', emailId, timestamp];
        break;
      case 'bounce':
      case 'dropped':
        updateQuery = `UPDATE emails SET status = $1, "bouncedAt" = $3, "updatedAt" = NOW() WHERE id = $2`;
        updateParams = ['bounced', emailId, timestamp];
        break;
      case 'spamreport':
        updateQuery = `UPDATE emails SET status = $1, "spamAt" = $3, "updatedAt" = NOW() WHERE id = $2`;
        updateParams = ['spam', emailId, timestamp];
        break;
      case 'processed':
        return true; // Acknowledge silently
      default:
        return true; // Unknown events, ignore silently
    }

    const result = await db.query(updateQuery, updateParams);
    return result.rowCount > 0;

  } catch (error) {
    // Only log actual database errors
    logger.error(`Database error for ${customerEmail}:`, error);
    return false;
  }
}

// Simple test endpoint
router.get('/sendgrid/test', (req: Request, res: Response) => {
  res.json({
    message: 'Webhook working',
    stats: webhookStats,
    timestamp: new Date().toISOString()
  });
});

export default router;
```

## src/routes/upload.ts
```typescript
// src/routes/upload.ts - NEW FILE
import { Router, Request, Response } from 'express';
import multer from 'multer';
import * as XLSX from 'xlsx';
import { authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/tab-separated-values'
    ];

    if (allowedTypes.includes(file.mimetype) || 
        file.originalname.toLowerCase().endsWith('.csv') ||
        file.originalname.toLowerCase().endsWith('.xlsx') ||
        file.originalname.toLowerCase().endsWith('.xls') ||
        file.originalname.toLowerCase().endsWith('.tsv')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only CSV, Excel, and TSV files are allowed.'));
    }
  }
});

interface Customer {
  name: string;
  email: string;
  originalRow: number;
  originalSheet?: string;
}

interface OrderCustomer {
  firstName: string;
  lastName: string;
  email: string;
  orderNumber: string;
  orderDate: string;
  despatchDate: string;
  originalRow: number;
  originalSheet?: string;
  displayName?: string;
  skipReason?: string;
}

interface ProcessedData {
  customers: Customer[];
  skipped: OrderCustomer[];
  sheets: string[];
  headers: string[][];
  validation: {
    valid: number;
    skipped: number;
    skipReasons: Record<string, number>;
  };
  summary: {
    total: number;
    toSend: number;
    skipped: number;
    skipReasons: Record<string, number>;
  };
}
const isWithin36BusinessHours = (orderDateStr: string, despatchDateStr: string): boolean => {
  if (!orderDateStr || !despatchDateStr || orderDateStr.trim() === '' || despatchDateStr.trim() === '') return false;

  try {
    // Parse both dates
    const parseDate = (dateStr: string): Date => {
      if (dateStr.includes(' ')) {
        // Format with time
        const [datePart, timePart] = dateStr.split(' ');

        if (datePart.includes('/')) {
          // DD/MM/YYYY HH:MM:SS format
          const [day, month, year] = datePart.split('/');
          const [hours, minutes, seconds] = (timePart || '00:00:00').split(':');

          return new Date(
            parseInt(year), 
            parseInt(month) - 1, 
            parseInt(day),
            parseInt(hours || '0'),
            parseInt(minutes || '0'),
            parseInt(seconds || '0')
          );
        } else {
          // YYYY-MM-DD HH:MM:SS format
          return new Date(dateStr);
        }
      } else {
        // Just date without time
        if (dateStr.includes('/')) {
          // DD/MM/YYYY format
          const [day, month, year] = dateStr.split('/');
          return new Date(parseInt(year), parseInt(month) - 1, parseInt(day), 12, 0, 0);
        } else {
          // YYYY-MM-DD format
          return new Date(dateStr + 'T12:00:00');
        }
      }
    };

    const orderDate = parseDate(orderDateStr);
    const despatchDate = parseDate(despatchDateStr);

    // Check if dates are valid
    if (isNaN(orderDate.getTime()) || isNaN(despatchDate.getTime())) {
      console.error('Invalid dates:', { orderDateStr, despatchDateStr });
      return false;
    }

    // Calculate business hours between ORDER and DESPATCH
    let businessHours = 0;
    let currentDate = new Date(orderDate);

    while (currentDate < despatchDate) {
      const dayOfWeek = currentDate.getDay(); // 0 = Sunday, 6 = Saturday

      // Skip weekends (Saturday = 6, Sunday = 0)
      if (dayOfWeek !== 0 && dayOfWeek !== 6) {
        const endOfDay = new Date(currentDate);
        endOfDay.setHours(23, 59, 59, 999);

        const endTime = endOfDay < despatchDate ? endOfDay : despatchDate;
        const hoursThisDay = (endTime.getTime() - currentDate.getTime()) / (1000 * 60 * 60);

        businessHours += hoursThisDay;
      }

      // Move to next day
      currentDate.setDate(currentDate.getDate() + 1);
      currentDate.setHours(0, 0, 0, 0);
    }

    return businessHours <= 36;

  } catch (error) {
    console.error('Error parsing dates:', { orderDateStr, despatchDateStr }, error);
    return false;
  }
};

const formatCustomerName = (firstName: string, lastName: string): string => {
  const titleWords = ['MR', 'MRS', 'MISS', 'MS', 'DR', 'SIR', 'LADY'];
  const firstNameUpper = firstName.toUpperCase();

  // Check if firstName is a title or single letter - these need special handling
  const isTitle = titleWords.includes(firstNameUpper);
  const isSingleLetter = firstName.length === 1;

  if (isTitle || isSingleLetter) {
    // Smart handling: Use both first name (title/initial) and last name
    // Examples: "Hello MR Smith", "Hello K Pudney"
    return `${firstName} ${lastName}`.trim();
  } else {
    // Default: Use just the first name for personal feel
    // Examples: "Hello John", "Hello Sarah", "Hello Michael"
    return firstName;
  }
};

const detectOrderColumns = (headers: string[]): {
  firstName: number;
  lastName: number;
  email: number;
  orderNumber: number;
  orderDate: number;
  despatchDate: number;
} => {
  const headerRow = headers.map(h => (h || '').toString().toLowerCase());

  const firstNameIndex = headerRow.findIndex(h => 
    h.includes('first') || h.includes('fname') || h.includes('given') || 
    h.includes('customer') && h.includes('first')
  );

  const lastNameIndex = headerRow.findIndex(h => 
    h.includes('last') || h.includes('surname') || h.includes('family') ||
    h.includes('customer') && h.includes('last')
  );

  const emailIndex = headerRow.findIndex(h => 
    h.includes('email') || h.includes('mail') || h.includes('@')
  );

  const orderNumberIndex = headerRow.findIndex(h => 
    (h.includes('order') && (h.includes('number') || h.includes('id') || h.includes('#'))) ||
    h.includes('order_number') || h.includes('orderid') || h.includes('order_id')
  );

  const orderDateIndex = headerRow.findIndex(h => 
    (h.includes('order') && h.includes('date')) || 
    h.includes('created') || h.includes('placed') ||
    h.includes('order_date') || h.includes('orderdate')
  );

  const despatchDateIndex = headerRow.findIndex(h => 
    h.includes('despatch') || h.includes('dispatch') || 
    h.includes('shipped') || h.includes('delivery')
  );

  return {
    firstName: firstNameIndex >= 0 ? firstNameIndex : 0,
    lastName: lastNameIndex >= 0 ? lastNameIndex : 1,
    email: emailIndex >= 0 ? emailIndex : 2,
    orderNumber: orderNumberIndex >= 0 ? orderNumberIndex : 3,
    orderDate: orderDateIndex >= 0 ? orderDateIndex : 4,
    despatchDate: despatchDateIndex >= 0 ? despatchDateIndex : 5
  };
};

const processOrderData = (
  data: string[][], 
  columnMappings: {
    firstName: number;
    lastName: number;
    email: number;
    orderNumber: number;
    orderDate: number;
    despatchDate: number;
  },
  sheetName?: string
): { toSend: OrderCustomer[]; skipped: OrderCustomer[] } => {

  const toSend: OrderCustomer[] = [];
  const skipped: OrderCustomer[] = [];
  const processedOrders = new Set<string>();
  const emailOrderCombos = new Map<string, Set<string>>();

  // Skip header row (index 0)
  for (let i = 1; i < data.length; i++) {
    const row = data[i];

    // Skip rows that don't have enough columns
    if (row.length <= Math.max(...Object.values(columnMappings))) continue;

    const firstName = (row[columnMappings.firstName] || '').toString().trim();
    const lastName = (row[columnMappings.lastName] || '').toString().trim();
    const email = (row[columnMappings.email] || '').toString().trim().toLowerCase();
    const orderNumber = (row[columnMappings.orderNumber] || '').toString().trim();
    const orderDate = (row[columnMappings.orderDate] || '').toString().trim();
    const despatchDate = (row[columnMappings.despatchDate] || '').toString().trim();

    const customer: OrderCustomer = {
      firstName,
      lastName,
      email,
      orderNumber,
      orderDate,
      despatchDate,
      originalRow: i + 1,
      originalSheet: sheetName
    };

    // Business Rule 1: Skip if no order number
    if (!orderNumber) {
      customer.skipReason = 'No order number';
      skipped.push(customer);
      continue;
    }

    // Business Rule 2: Skip if no email or invalid email
    if (!email || !validateEmail(email)) {
      customer.skipReason = 'Invalid or missing email';
      skipped.push(customer);
      continue;
    }

    // Business Rule 3: Skip if no name data
    if (!firstName && !lastName) {
      customer.skipReason = 'No customer name';
      skipped.push(customer);
      continue;
    }

    // Business Rule 4: Skip if despatch date is older than 36 business hours
      if (!isWithin36BusinessHours(orderDate, despatchDate)) {
      customer.skipReason = 'Despatch date older than 36 business hours';
      skipped.push(customer);
      continue;
    }

    // Business Rule 5: Only send once per order number
    if (processedOrders.has(orderNumber)) {
      customer.skipReason = 'Duplicate order number';
      skipped.push(customer);
      continue;
    }

    // Business Rule 6: For same email, only send if order number AND date are different
    if (!emailOrderCombos.has(email)) {
      emailOrderCombos.set(email, new Set());
    }

    const emailOrders = emailOrderCombos.get(email)!;
    const orderKey = `${orderNumber}_${orderDate}`;

    if (emailOrders.has(orderKey)) {
      customer.skipReason = 'Same email with same order number and date';
      skipped.push(customer);
      continue;
    }

    // Business Rule 7: Smart name formatting
    customer.displayName = formatCustomerName(firstName, lastName);

    // If we get here, the customer should be included
    processedOrders.add(orderNumber);
    emailOrders.add(orderKey);
    toSend.push(customer);
  }

  return { toSend, skipped };
};

const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const parseCSV = (text: string, delimiter: string = ','): string[][] => {
  const lines = text.split('\n');
  const result: string[][] = [];

  for (let line of lines) {
    if (line.trim() === '') continue;

    // Handle quoted fields
    const row: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"' && (i === 0 || line[i-1] === delimiter)) {
        inQuotes = true;
      } else if (char === '"' && inQuotes && (i === line.length - 1 || line[i+1] === delimiter)) {
        inQuotes = false;
      } else if (char === delimiter && !inQuotes) {
        row.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    row.push(current.trim());

    result.push(row);
  }

  return result;
};

// POST /api/upload/process - Process uploaded file
router.post('/process', 
  authenticateToken,
  upload.single('file'),
  async (req: Request, res: Response) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No file uploaded'
        });
      }

      const file = req.file;
      const fileName = file.originalname.toLowerCase();
      let allSheetData: Record<string, string[][]> = {};
      let sheets: string[] = [];

      logger.info(`Processing file: ${file.originalname}, size: ${file.size}, type: ${file.mimetype}`);

      // Process based on file type
      if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
        // Excel file processing
        const workbook = XLSX.read(file.buffer, {
          type: 'buffer',
          cellText: false,
          cellDates: true,
          raw: false
        });

        sheets = workbook.SheetNames;

        for (const sheetName of sheets) {
          const worksheet = workbook.Sheets[sheetName];
          const jsonData = XLSX.utils.sheet_to_json(worksheet, {
            header: 1,
            raw: false,
            dateNF: 'yyyy-mm-dd',
            defval: ''
          }) as string[][];

          // Filter out completely empty rows
          const filteredData = jsonData.filter(row => 
            row.some(cell => cell && cell.toString().trim() !== '')
          );

          allSheetData[sheetName] = filteredData;
        }

      } else if (fileName.endsWith('.csv')) {
        // CSV file processing
        const text = file.buffer.toString('utf-8');
        const csvData = parseCSV(text);
        allSheetData['Sheet1'] = csvData;
        sheets = ['Sheet1'];

      } else if (fileName.endsWith('.tsv')) {
        // TSV file processing
        const text = file.buffer.toString('utf-8');
        const tsvData = parseCSV(text, '\t');
        allSheetData['Sheet1'] = tsvData;
        sheets = ['Sheet1'];

      } else {
        return res.status(400).json({
          success: false,
          error: 'Unsupported file format'
        });
      }

      // Process first sheet by default
      const firstSheet = sheets[0];
      const firstSheetData = allSheetData[firstSheet];

      if (!firstSheetData || firstSheetData.length < 2) {
        return res.status(400).json({
          success: false,
          error: 'File must contain at least a header row and one data row'
        });
      }

      // Apply business logic processing
      const columnMappings = detectOrderColumns(firstSheetData[0]);
      const { toSend, skipped } = processOrderData(firstSheetData, columnMappings, firstSheet);

      // Generate summary statistics
      const skipReasons: Record<string, number> = {};
      skipped.forEach(customer => {
        const reason = customer.skipReason || 'Unknown';
        skipReasons[reason] = (skipReasons[reason] || 0) + 1;
      });

      // Convert to existing Customer format for compatibility
      const validCustomers: Customer[] = toSend.map(customer => ({
        name: customer.displayName || customer.firstName,
        email: customer.email,
        originalRow: customer.originalRow,
        originalSheet: customer.originalSheet
      }));

      const response: ProcessedData = {
        customers: validCustomers,
        skipped: skipped,
        sheets,
        headers: [firstSheetData[0]],
        validation: {
          valid: toSend.length,
          skipped: skipped.length,
          skipReasons: skipReasons
        },
        summary: {
          total: firstSheetData.length - 1,
          toSend: toSend.length,
          skipped: skipped.length,
          skipReasons: skipReasons
        }
      };

      logger.info(`Order file processed: ${toSend.length} customers to send, ${skipped.length} skipped`);

      res.json({
        success: true,
        data: response
      });

    } catch (error) {
      logger.error('File processing error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to process file',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);

export default router;
```

## src/services/emailService.ts
```typescript
// src/services/emailService.ts - CLEANED VERSION WITH REDUCED LOGGING
import sgMail from '@sendgrid/mail';
import { config } from '../config/environment';
import { logger } from '../utils/logger';
import { db } from '../lib/prisma';

sgMail.setApiKey(config.sendgrid.apiKey);

export interface Customer {
  name: string;
  email: string;
  customFields?: Record<string, string>;
}

export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
  customer: Customer;
}

export interface Company {
  id: number;
  name: string;
  fromEmail: string;
  fromName: string;
  industry?: string;
}

export interface ReviewPlatform {
  id: number;
  platform: string;
  name: string;
  reviewUrl: string;
  isActive: boolean;
}

export interface EmailTemplate {
  id: number;
  name: string;
  subject: string;
  html: string;
  platform: string;
}

export class EmailService {
  async sendReviewRequestEmails(
    customers: Customer[],
    company: Company,
    template: EmailTemplate,
    reviewPlatform: ReviewPlatform,
    userId?: number | string
  ): Promise<EmailSendResult[]> {
    const results: EmailSendResult[] = [];

    // Simple platform validation
    if (template.platform !== reviewPlatform.platform) {
      throw new Error(`Template platform (${template.platform}) doesn't match review platform (${reviewPlatform.platform})`);
    }

    for (const customer of customers) {
      try {
        const personalizedTemplate = this.personalizeTemplate(
          template, 
          customer, 
          company, 
          reviewPlatform
        );

        const msg = {
          to: customer.email,
          from: {
            email: company.fromEmail,
            name: company.fromName // Use the display name from user settings
          },
          subject: personalizedTemplate.subject,
          html: personalizedTemplate.html,
          trackingSettings: {
            clickTracking: { enable: true, enableText: false },
            openTracking: { enable: true }
          },
          // Categories and custom args for webhook filtering
          categories: ['review_request', reviewPlatform.platform.toLowerCase()],
          customArgs: {
            source: 'review_requester',
            companyId: company.id.toString(),
            templateId: template.id.toString(),
            reviewPlatformId: reviewPlatform.id.toString(),
            platform: reviewPlatform.platform,
            customerEmail: customer.email,
            customerName: customer.name,
            userId: userId?.toString() || '1'
          }
        };

        const response = await sgMail.send(msg);
        const messageId = response[0].headers['x-message-id'] as string;

        results.push({
          success: true,
          messageId: messageId,
          customer
        });

        // Log successful send to database
        await this.logEmailToDatabase({
          companyId: company.id,
          templateId: template.id,
          reviewPlatformId: reviewPlatform.id,
          customerEmail: customer.email,
          customerName: customer.name,
          status: 'SENT',
          messageId: messageId,
          userId: userId,
          sendgridMessageId: messageId
        });

        // Only log on success (removed detailed individual email logs)
        if (results.length === 1) {
          logger.info(`✅ Email campaign started: sending to ${customers.length} customers`);
        }

        // Add small delay to avoid rate limiting
        await this.delay(100);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';

        results.push({
          success: false,
          error: errorMessage,
          customer
        });

        // Log failed send to database
        await this.logEmailToDatabase({
          companyId: company.id,
          templateId: template.id,
          reviewPlatformId: reviewPlatform.id,
          customerEmail: customer.email,
          customerName: customer.name,
          status: 'FAILED',
          error: errorMessage,
          userId: userId
        });

        logger.error(`❌ Failed to send email to ${customer.email}: ${errorMessage}`);
      }
    }

    // Summary log instead of individual logs
    const successCount = results.filter(r => r.success).length;
    const failureCount = results.filter(r => !r.success).length;

    if (successCount > 0) {
      logger.info(`📧 Campaign completed: ${successCount} sent, ${failureCount} failed`);
    }

    return results;
  }

  private personalizeTemplate(
    template: EmailTemplate, 
    customer: Customer, 
    company: Company,
    reviewPlatform: ReviewPlatform
  ): { subject: string; html: string } {

    // Simple platform name mapping
    const platformNames: Record<string, string> = {
      'TRUSTPILOT': 'Trustpilot',
      'GOOGLE': 'Google My Business',
      'YELP': 'Yelp',
      'FACEBOOK': 'Facebook',
      'AMAZON': 'Amazon',
      'TRIPADVISOR': 'TripAdvisor',
      'CUSTOM': 'Review Platform'
    };

    const variables = {
      // Customer variables
      customerName: customer.name,

      // Company variables
      companyName: company.name,
      fromName: company.fromName,
      fromEmail: company.fromEmail,
      industry: company.industry || 'business',

      // Platform variables
      reviewUrl: reviewPlatform.reviewUrl,
      platformName: platformNames[reviewPlatform.platform] || reviewPlatform.platform,
      reviewPlatformName: reviewPlatform.name,
      trustpilotLink: reviewPlatform.reviewUrl, // For backward compatibility

      // Custom fields from customer
      ...customer.customFields
    };

    let subject = template.subject;
    let html = template.html;

    // Replace variables in format {{variableName}}
    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`{{${key}}}`, 'g');
      subject = subject.replace(regex, value || '');
      html = html.replace(regex, value || '');
    }

    return { subject, html };
  }

  private async logEmailToDatabase(logData: {
    companyId: number;
    templateId: number;
    reviewPlatformId: number;
    customerEmail: string;
    customerName: string;
    status: 'SENT' | 'FAILED' | 'DELIVERED' | 'OPENED' | 'CLICKED' | 'BOUNCED' | 'SPAM';
    messageId?: string;
    error?: string;
    userId?: number | string;
    sendgridMessageId?: string;
  }): Promise<void> {
    try {
      // Convert userId to string consistently
      let userIdString = '1'; // Default fallback

      if (logData.userId) {
        userIdString = logData.userId.toString();
      }

      // Ensure we have a valid user in the database
      await this.ensureUserExists(userIdString);

      // Create a more descriptive subject line
      const subjectLine = `Review Request for ${logData.customerName}`;
      const contentDescription = `${logData.status} - Email ${logData.status.toLowerCase()} to ${logData.customerName} (${logData.customerEmail})`;

      // Create email log record using direct SQL
      await db.query(`
        INSERT INTO emails (
          id, "to", subject, content, status, "sentAt", 
          "userId", "campaignId", "sendgridMessageId", "createdAt", "updatedAt"
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, $4, $5, 
          $6, $7, $8, NOW(), NOW()
        )
      `, [
        logData.customerEmail,
        subjectLine,
        contentDescription,
        logData.status.toLowerCase(),
        logData.status === 'SENT' ? new Date() : null,
        userIdString,
        null, // campaign ID - will be null for now
        logData.sendgridMessageId || logData.messageId
      ]);

    } catch (error) {
      // Only log database errors, don't spam console with successful saves
      logger.error('Database logging error:', error);

      // Try fallback approach
      try {
        await this.createBasicEmailLog(logData);
      } catch (fallbackError) {
        logger.error('Fallback email logging failed:', fallbackError);
      }
    }
  }

  private async ensureUserExists(userId: string): Promise<void> {
    try {
      // Check if user exists
      const userCheck = await db.query(
        'SELECT id FROM users WHERE id = $1',
        [userId]
      );

      // If user doesn't exist, create a basic user record
      if (userCheck.rows.length === 0) {
        await db.query(`
          INSERT INTO users (id, email, name, "createdAt", "updatedAt")
          VALUES ($1, $2, $3, NOW(), NOW())
          ON CONFLICT (id) DO NOTHING
        `, [
          userId,
          'system@reviewrequester.com',
          'System User'
        ]);
      }
    } catch (error) {
      // Don't throw - we'll try to proceed anyway
    }
  }

  private async createBasicEmailLog(logData: any): Promise<void> {
    try {
      // Simplified logging as fallback
      await db.query(`
        INSERT INTO emails (
          id, "to", subject, content, status, "userId", "createdAt", "updatedAt"
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, $4, $5, NOW(), NOW()
        )
      `, [
        logData.customerEmail,
        `Email to ${logData.customerName}`,
        `Status: ${logData.status}`,
        logData.status.toLowerCase(),
        '1' // Fallback to user ID 1
      ]);
    } catch (error) {
      // Silent failure for fallback
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Validate email addresses
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate customer data
  static validateCustomers(customers: any[]): { valid: Customer[]; invalid: any[] } {
    const valid: Customer[] = [];
    const invalid: any[] = [];

    for (const customer of customers) {
      if (
        customer &&
        typeof customer.name === 'string' &&
        typeof customer.email === 'string' &&
        customer.name.trim() &&
        this.isValidEmail(customer.email)
      ) {
        valid.push({
          name: customer.name.trim(),
          email: customer.email.toLowerCase().trim(),
          customFields: customer.customFields || {}
        });
      } else {
        invalid.push(customer);
      }
    }

    return { valid, invalid };
  }

  // Get email delivery statistics
  static async getDeliveryStats(userId: string, days: number = 30): Promise<any> {
    try {
      const result = await db.query(`
        SELECT 
          COUNT(*) as total_sent,
          COUNT(CASE WHEN "deliveredAt" IS NOT NULL THEN 1 END) as delivered,
          COUNT(CASE WHEN "openedAt" IS NOT NULL THEN 1 END) as opened,
          COUNT(CASE WHEN "clickedAt" IS NOT NULL THEN 1 END) as clicked,
          COUNT(CASE WHEN "bouncedAt" IS NOT NULL THEN 1 END) as bounced,
          COUNT(CASE WHEN "spamAt" IS NOT NULL THEN 1 END) as spam,
          AVG("openCount") as avg_opens,
          AVG("clickCount") as avg_clicks
        FROM emails 
        WHERE "userId" = $1 
        AND "createdAt" >= NOW() - INTERVAL '${days} days'
      `, [userId]);

      return result.rows[0] || {};
    } catch (error) {
      logger.error('Error fetching delivery stats:', error);
      return {};
    }
  }
}
```

## src/types/database.ts
```typescript
// src/types/database.ts

  export enum PlatformType {
  TRUSTPILOT = 'TRUSTPILOT',
  GOOGLE = 'GOOGLE',
  YELP = 'YELP',
  FACEBOOK = 'FACEBOOK',
  AMAZON = 'AMAZON',
  TRIPADVISOR = 'TRIPADVISOR',
  CUSTOM = 'CUSTOM'
  }

export interface ReviewPlatform {
  id: number;
  platform: PlatformType;
  name: string;
  reviewUrl: string;
  isActive: boolean;
  isDefault: boolean;
  companyId: number;
  createdAt: Date;
  updatedAt: Date;
}

  export interface User {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface Company {
  id: number;
  name: string;
  trustpilotUrl: string;
  fromEmail: string;
  fromName: string;
  website?: string;
  industry?: string;
  isActive: boolean;
  userId: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface EmailTemplate {
  id: number;
  name: string;
  subject: string;
  html: string;
  platform: PlatformType;
  isDefault: boolean;
  isActive: boolean;
  companyId: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Campaign {
  id: number;
  name: string;
  status: CampaignStatus;
  scheduledAt?: Date;
  sentAt?: Date;
  totalEmails: number;
  sentEmails: number;
  failedEmails: number;
  companyId: number;
  templateId: number;
  customers: CustomerData[];
  createdAt: Date;
  updatedAt: Date;
}

export interface EmailLog {
  id: number;
  customerEmail: string;
  customerName: string;
  status: EmailStatus;
  messageId?: string;
  error?: string;
  sentAt?: Date;
  deliveredAt?: Date;
  openedAt?: Date;
  clickedAt?: Date;
  companyId: number;
  templateId: number;
  campaignId?: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Subscription {
  id: number;
  plan: SubscriptionPlan;
  status: SubscriptionStatus;
  emailsPerMonth: number;
  emailsUsed: number;
  currentPeriodStart: Date;
  currentPeriodEnd: Date;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  companyId: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface CustomerData {
  name: string;
  email: string;
  customFields?: Record<string, string>;
}

export enum CampaignStatus {
  DRAFT = 'DRAFT',
  SCHEDULED = 'SCHEDULED',
  SENDING = 'SENDING',
  SENT = 'SENT',
  FAILED = 'FAILED'
}

export enum EmailStatus {
  SENT = 'SENT',
  DELIVERED = 'DELIVERED',
  FAILED = 'FAILED',
  OPENED = 'OPENED',
  CLICKED = 'CLICKED',
  BOUNCED = 'BOUNCED',
  SPAM = 'SPAM'
}

export enum SubscriptionPlan {
  STARTER = 'STARTER',
  GROWTH = 'GROWTH',
  PRO = 'PRO',
  ENTERPRISE = 'ENTERPRISE'
}

export enum SubscriptionStatus {
  ACTIVE = 'ACTIVE',
  CANCELED = 'CANCELED',
  PAST_DUE = 'PAST_DUE',
  UNPAID = 'UNPAID'
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

// Request types
export interface CreateCompanyRequest {
  name: string;
  trustpilotUrl: string;
  fromEmail: string;
  fromName: string;
  website?: string;
  industry?: string;
}

export interface SendEmailRequest {
  customers: CustomerData[];
  templateId: number;
  reviewPlatformId: number;
  campaignName?: string;
  scheduledAt?: string;
}

export interface CreateTemplateRequest {
  name: string;
  subject: string;
  html: string;
  isDefault?: boolean;
}
// ADD these to your existing types file:

export enum PlatformType {
  TRUSTPILOT = 'TRUSTPILOT',
  GOOGLE = 'GOOGLE',
  YELP = 'YELP',
  FACEBOOK = 'FACEBOOK',
  AMAZON = 'AMAZON',
  TRIPADVISOR = 'TRIPADVISOR',
  CUSTOM = 'CUSTOM'
}

export interface ReviewPlatform {
  id: number;
  platform: PlatformType;
  name: string;
  reviewUrl: string;
  isActive: boolean;
  isDefault: boolean;
  companyId: number;
  createdAt: Date;
  updatedAt: Date;
}

// UPDATE the existing EmailTemplate interface:
export interface EmailTemplate {
  id: number;
  name: string;
  subject: string;
  html: string;
  platform: PlatformType;
  isDefault: boolean;
  isActive: boolean;
  companyId: number;
  createdAt: Date;
  updatedAt: Date;
}

// UPDATE the existing SendEmailRequest:
export interface SendEmailRequest {
  customers: CustomerData[];
  templateId: number;
  reviewPlatformId: number;
  campaignName?: string;
  scheduledAt?: string;
}
```

## src/utils/logger.ts
```typescript
import winston from 'winston';
import { config } from '../config/environment';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

export const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: { service: 'trustpilot-email-agent' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Add file logging in production
if (config.nodeEnv === 'production') {
  logger.add(new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error'
  }));

  logger.add(new winston.transports.File({
    filename: 'logs/combined.log'
  }));
}
```

## src/lib/prisma.ts
```typescript
// src/lib/prisma.ts - Now using direct PostgreSQL connection
import { Pool, PoolClient } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
})

export const db = {
  async query(text: string, params?: any[]) {
    const client = await pool.connect()
    try {
      const result = await client.query(text, params)
      return result
    } finally {
      client.release()
    }
  },

  async getClient(): Promise<PoolClient> {
    return await pool.connect()
  },

  async end() {
    await pool.end()
  }
}

// Test connection
export async function testConnection() {
  try {
    const result = await db.query('SELECT NOW() as current_time')
    console.log('✅ Database connected successfully:', result.rows[0])
    return true
  } catch (error) {
    console.error('❌ Database connection failed:', error)
    return false
  }
}

// For backward compatibility, export as prisma
export const prisma = db

export default db
```

## dist/index.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// src/index.ts - Main server file
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const environment_1 = require("./config/environment");
const errorHandler_1 = require("./middleware/errorHandler");
const logger_1 = require("./utils/logger");
const auth_1 = __importDefault(require("./routes/auth"));
const email_1 = __importDefault(require("./routes/email"));
const campaigns_1 = __importDefault(require("./routes/campaigns"));
const app = (0, express_1.default)();
// Security middleware
app.use((0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"]
        }
    }
}));
app.use((0, cors_1.default)({
    origin: process.env.NODE_ENV === 'production'
        ? process.env.FRONTEND_URL
        : 'http://localhost:3000',
    credentials: true
}));
// Rate limiting
const limiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);
// Body parsing
app.use(express_1.default.json({ limit: '10mb' }));
app.use(express_1.default.urlencoded({ extended: true }));
app.use(express_1.default.static('.')); // Serve static files from root directory
// Logging
app.use((req, res, next) => {
    logger_1.logger.info(`${req.method} ${req.path} - ${req.ip}`);
    next();
});
// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});
// Routes
app.use('/api/auth', auth_1.default);
app.use('/api/email', email_1.default);
app.use('/api/campaigns', campaigns_1.default);
// Test page route
app.get('/test', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>API Test</title></head>
    <body>
      <h1>Test API Endpoints</h1>
      <p>API Base: <code>${req.protocol}://${req.get('host')}</code></p>
      <button onclick="testRegister()">Test Register</button>
      <script>
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
      </script>
    </body>
    </html>
  `);
});
// Error handling
app.use(errorHandler_1.errorHandler);
// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});
const PORT = environment_1.config.port;
app.listen(PORT, () => {
    logger_1.logger.info(`🚀 Server running on port ${PORT}`);
    logger_1.logger.info(`📧 SendGrid configured: ${!!environment_1.config.sendgrid.apiKey}`);
    logger_1.logger.info(`🌍 Environment: ${environment_1.config.nodeEnv}`);
});
exports.default = app;
//# sourceMappingURL=index.js.map
```

## dist/config/environment.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
// src/config/environment.ts
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const required = (key) => {
    const value = process.env[key];
    if (!value) {
        throw new Error(`Missing required environment variable: ${key}`);
    }
    return value;
};
const optional = (key, defaultValue = '') => {
    return process.env[key] || defaultValue;
};
exports.config = {
    nodeEnv: optional('NODE_ENV', 'development'),
    port: parseInt(optional('PORT', '3000')),
    // Database
    database: {
        url: required('DATABASE_URL'),
    },
    // SendGrid
    sendgrid: {
        apiKey: required('SENDGRID_API_KEY'),
    },
    // JWT
    jwt: {
        secret: required('JWT_SECRET'),
        expiresIn: optional('JWT_EXPIRES_IN', '7d'),
    },
    // Frontend
    frontend: {
        url: optional('FRONTEND_URL', 'http://localhost:3000'),
    },
    // Redis (for caching/sessions)
    redis: {
        url: optional('REDIS_URL', 'redis://localhost:6379'),
    },
    // App settings
    app: {
        name: optional('APP_NAME', 'Trustpilot Email Agent'),
        supportEmail: optional('SUPPORT_EMAIL', 'support@yourdomain.com'),
    }
};
// Validate critical config on startup
const validateConfig = () => {
    try {
        required('DATABASE_URL');
        required('SENDGRID_API_KEY');
        required('JWT_SECRET');
        console.log('✅ Configuration validated successfully');
    }
    catch (error) {
        console.error('❌ Configuration validation failed:', error);
        process.exit(1);
    }
};
validateConfig();
//# sourceMappingURL=environment.js.map
```

## dist/utils/logger.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const environment_1 = require("../config/environment");
const logFormat = winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json());
exports.logger = winston_1.default.createLogger({
    level: environment_1.config.nodeEnv === 'production' ? 'info' : 'debug',
    format: logFormat,
    defaultMeta: { service: 'trustpilot-email-agent' },
    transports: [
        new winston_1.default.transports.Console({
            format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
        })
    ]
});
// Add file logging in production
if (environment_1.config.nodeEnv === 'production') {
    exports.logger.add(new winston_1.default.transports.File({
        filename: 'logs/error.log',
        level: 'error'
    }));
    exports.logger.add(new winston_1.default.transports.File({
        filename: 'logs/combined.log'
    }));
}
//# sourceMappingURL=logger.js.map
```

## dist/middleware/errorHandler.js
```javascript
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorHandler = void 0;
const logger_1 = require("../utils/logger");
const errorHandler = (err, req, res, next) => {
    const { statusCode = 500, message, stack } = err;
    logger_1.logger.error('Error occurred:', {
        error: message,
        statusCode,
        stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    // Don't leak error details in production
    const errorMessage = process.env.NODE_ENV === 'production'
        ? 'Something went wrong'
        : message;
    res.status(statusCode).json({
        success: false,
        error: errorMessage,
        ...(process.env.NODE_ENV === 'development' && { stack })
    });
};
exports.errorHandler = errorHandler;
//# sourceMappingURL=errorHandler.js.map
```

## dist/middleware/validation.js
```javascript
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateRequest = void 0;
const zod_1 = require("zod");
const validateRequest = (schema) => {
    return (req, res, next) => {
        try {
            schema.parse({
                body: req.body,
                query: req.query,
                params: req.params
            });
            next();
        }
        catch (error) {
            if (error instanceof zod_1.ZodError) {
                const errors = error.errors.map(err => ({
                    field: err.path.join('.'),
                    message: err.message
                }));
                return res.status(400).json({
                    success: false,
                    error: 'Validation failed',
                    details: errors
                });
            }
            return res.status(500).json({
                success: false,
                error: 'Internal validation error'
            });
        }
    };
};
exports.validateRequest = validateRequest;
//# sourceMappingURL=validation.js.map
```

## dist/middleware/auth.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const environment_1 = require("../config/environment");
const logger_1 = require("../utils/logger");
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Access token required'
        });
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, environment_1.config.jwt.secret);
        req.user = decoded;
        next();
    }
    catch (error) {
        logger_1.logger.warn(`Invalid token attempt: ${error}`);
        return res.status(403).json({
            success: false,
            error: 'Invalid or expired token'
        });
    }
};
exports.authenticateToken = authenticateToken;
//# sourceMappingURL=auth.js.map
```

## dist/routes/auth.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const environment_1 = require("../config/environment");
const validation_1 = require("../middleware/validation");
const logger_1 = require("../utils/logger");
const zod_1 = require("zod");
const router = (0, express_1.Router)();
// Validation schemas
const registerSchema = zod_1.z.object({
    body: zod_1.z.object({
        email: zod_1.z.string().email('Valid email is required'),
        password: zod_1.z.string().min(8, 'Password must be at least 8 characters'),
        firstName: zod_1.z.string().min(1, 'First name is required'),
        lastName: zod_1.z.string().min(1, 'Last name is required')
    })
});
const loginSchema = zod_1.z.object({
    body: zod_1.z.object({
        email: zod_1.z.string().email('Valid email is required'),
        password: zod_1.z.string().min(1, 'Password is required')
    })
});
// POST /api/auth/register
router.post('/register', (0, validation_1.validateRequest)(registerSchema), async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;
        // TODO: Check if user already exists in database
        // const existingUser = await db.user.findUnique({ where: { email } });
        // if (existingUser) {
        //   return res.status(400).json({
        //     success: false,
        //     error: 'User with this email already exists'
        //   });
        // }
        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt_1.default.hash(password, saltRounds);
        // TODO: Create user in database
        const user = {
            id: Date.now(), // Temporary ID
            email: email.toLowerCase(),
            firstName,
            lastName,
            password: hashedPassword,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        // Generate JWT token
        const token = jsonwebtoken_1.default.sign({ id: user.id, email: user.email }, environment_1.config.jwt.secret, { expiresIn: environment_1.config.jwt.expiresIn });
        logger_1.logger.info(`New user registered: ${email}`);
        res.status(201).json({
            success: true,
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName
                },
                token
            },
            message: 'User registered successfully'
        });
    }
    catch (error) {
        logger_1.logger.error('Error in user registration:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to register user'
        });
    }
});
// POST /api/auth/login
router.post('/login', (0, validation_1.validateRequest)(loginSchema), async (req, res) => {
    try {
        const { email, password } = req.body;
        // TODO: Get user from database
        // const user = await db.user.findUnique({ 
        //   where: { email: email.toLowerCase() } 
        // });
        // Mock user for now
        const user = {
            id: 1,
            email: 'charlie.gilbert@ransomspares.co.uk',
            password: await bcrypt_1.default.hash('password123', 12), // Mock hashed password
            firstName: 'Charlie',
            lastName: 'Gilbert',
            isActive: true
        };
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }
        // Verify password
        const isValidPassword = await bcrypt_1.default.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }
        // Generate JWT token
        const token = jsonwebtoken_1.default.sign({ id: user.id, email: user.email }, environment_1.config.jwt.secret, { expiresIn: environment_1.config.jwt.expiresIn });
        logger_1.logger.info(`User logged in: ${email}`);
        res.json({
            success: true,
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName
                },
                token
            },
            message: 'Login successful'
        });
    }
    catch (error) {
        logger_1.logger.error('Error in user login:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to login'
        });
    }
});
// POST /api/auth/logout
router.post('/logout', (req, res) => {
    // TODO: Invalidate token in database/Redis
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});
exports.default = router;
//# sourceMappingURL=auth.js.map
```

## dist/routes/email.js
```javascript
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// src/routes/email.ts
const express_1 = require("express");
const emailService_1 = require("../services/emailService");
const auth_1 = require("../middleware/auth");
const validation_1 = require("../middleware/validation");
const logger_1 = require("../utils/logger");
const zod_1 = require("zod");
const router = (0, express_1.Router)();
// Validation schemas
const sendEmailSchema = zod_1.z.object({
    body: zod_1.z.object({
        customers: zod_1.z.array(zod_1.z.object({
            name: zod_1.z.string().min(1, 'Name is required'),
            email: zod_1.z.string().email('Valid email is required'),
            customFields: zod_1.z.record(zod_1.z.string()).optional()
        })).min(1, 'At least one customer is required'),
        templateId: zod_1.z.number().int().positive('Valid template ID is required'),
        campaignName: zod_1.z.string().optional(),
        scheduledAt: zod_1.z.string().datetime().optional()
    })
});
// POST /api/email/send - Send review request emails
router.post('/send', auth_1.authenticateToken, (0, validation_1.validateRequest)(sendEmailSchema), async (req, res) => {
    try {
        const { customers, templateId, campaignName } = req.body;
        const userId = req.user.id;
        // Validate customers
        const { valid: validCustomers, invalid: invalidCustomers } = emailService_1.EmailService.validateCustomers(customers);
        if (validCustomers.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'No valid customers provided',
                data: { invalidCustomers }
            });
        }
        // TODO: Get company and template from database
        // For now, we'll use mock data similar to your original
        const company = {
            id: 1,
            name: 'Ransom Spares.co.uk Ltd',
            trustpilotUrl: 'https://uk.trustpilot.com/evaluate/ransomspares.co.uk',
            fromEmail: 'charlie.gilbert@ransomspares.co.uk',
            fromName: 'Charlie'
        };
        const template = {
            id: templateId,
            name: 'Default Review Request',
            subject: `We'd love your feedback, {{customerName}}!`,
            html: `
          <p>Hello {{customerName}},</p>
          <p>I hope this email finds you well. I'm reaching out to thank you for choosing us for your recent order, it really means a lot.</p>
          <p>As a family-run business based in Somerset, we take great pride in providing fast, reliable, and personalised service to each of our customers. We believe in what we do and are always striving to improve and grow.</p>
          <p>To help us spread the word and grow our customer base, we'd be incredibly grateful if you could leave us a review on Trustpilot. Your feedback will not only help us grow, but also allow others to see the level of service we provide.</p>
          <p>To leave your feedback, just click the link below:</p>
          <p><a href="{{trustpilotLink}}" target="_blank">{{trustpilotLink}}</a></p>
          <p>We truly appreciate your support and look forward to continuing to serve you in the future.</p>
          <p>Thank you again for your trust in us.</p>
          <p>Best regards,</p>
          <p>{{fromName}}<br/>
          {{companyName}}</p>
          <p><strong>E:</strong> <a href="mailto:{{fromEmail}}">{{fromEmail}}</a></p>
          <hr/>
          <small>
            {{companyName}}<br/>
            Supplier of spares and accessories for electric domestic appliances.<br/>
            The information in this email and attachments is confidential and intended for the sole use of the addressee(s). Access, copying, disclosure or re-use, in any way, of the information contained in this email and attachments by anyone other than the addressee(s) are unauthorised. If you have received this email in error, please return it to the sender and highlight the error. We accept no legal liability for the content of the message. Any opinions or views presented are solely the responsibility of the author and do not necessarily represent those of {{companyName}}. We cannot guarantee that this message has not been modified in transit, and this message should not be viewed as contractually binding. Although we have taken reasonable steps to ensure that this email and attachments are free from any virus, we advise that in keeping with good computing practice the recipient should ensure they are actually virus free.<br/>
            Without prejudice and subject to contract. Company Reg: 6779183. VAT Number: 948195871
          </small>
        `
        };
        // TODO: Check subscription limits
        // const subscription = await getSubscription(company.id);
        // if (subscription.emailsUsed + validCustomers.length > subscription.emailsPerMonth) {
        //   return res.status(403).json({
        //     success: false,
        //     error: 'Email limit exceeded for current subscription'
        //   });
        // }
        const emailService = new emailService_1.EmailService();
        const results = await emailService.sendReviewRequestEmails(validCustomers, company, template);
        const successCount = results.filter(r => r.success).length;
        const failureCount = results.filter(r => !r.success).length;
        // TODO: Create campaign record in database
        // const campaign = await createCampaign({
        //   name: campaignName || `Campaign ${new Date().toISOString()}`,
        //   companyId: company.id,
        //   templateId: template.id,
        //   customers: validCustomers,
        //   totalEmails: validCustomers.length,
        //   sentEmails: successCount,
        //   failedEmails: failureCount
        // });
        logger_1.logger.info(`Email campaign completed: ${successCount} sent, ${failureCount} failed`);
        res.json({
            success: true,
            message: `✅ ${successCount} emails sent successfully${failureCount ? `, ${failureCount} failed` : ''}`,
            data: {
                sent: successCount,
                failed: failureCount,
                invalidCustomers: invalidCustomers.length,
                results: results.map(r => ({
                    customerEmail: r.customer.email,
                    success: r.success,
                    error: r.error
                }))
            }
        });
    }
    catch (error) {
        logger_1.logger.error('Error in email send endpoint:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send emails',
            message: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});
// GET /api/email/templates - Get email templates for company
router.get('/templates', auth_1.authenticateToken, async (req, res) => {
    try {
        // TODO: Get templates from database
        const templates = [
            {
                id: 1,
                name: 'Default Review Request',
                subject: `We'd love your feedback, {{customerName}}!`,
                isDefault: true,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            }
        ];
        res.json({
            success: true,
            data: templates
        });
    }
    catch (error) {
        logger_1.logger.error('Error fetching templates:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch templates'
        });
    }
});
// POST /api/email/templates - Create new email template
router.post('/templates', auth_1.authenticateToken, async (req, res) => {
    try {
        const { name, subject, html, isDefault } = req.body;
        // TODO: Validate and create template in database
        const template = {
            id: Date.now(), // Temporary ID
            name,
            subject,
            html,
            isDefault: isDefault || false,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        res.status(201).json({
            success: true,
            data: template,
            message: 'Template created successfully'
        });
    }
    catch (error) {
        logger_1.logger.error('Error creating template:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create template'
        });
    }
});
exports.default = router;
//# sourceMappingURL=email.js.map
```

## dist/routes/campaigns.js
```javascript
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const logger_1 = require("../utils/logger");
const router = (0, express_1.Router)();
// GET /api/campaigns - Get all campaigns for user's companies
router.get('/', auth_1.authenticateToken, async (req, res) => {
    try {
        // TODO: Get campaigns from database
        const campaigns = [
            {
                id: 1,
                name: 'Q1 Review Campaign',
                status: 'SENT',
                totalEmails: 150,
                sentEmails: 148,
                failedEmails: 2,
                sentAt: new Date('2024-03-15'),
                createdAt: new Date('2024-03-14'),
                template: {
                    name: 'Default Review Request'
                }
            }
        ];
        res.json({
            success: true,
            data: campaigns
        });
    }
    catch (error) {
        logger_1.logger.error('Error fetching campaigns:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch campaigns'
        });
    }
});
// GET /api/campaigns/:id - Get specific campaign details
router.get('/:id', auth_1.authenticateToken, async (req, res) => {
    try {
        const campaignId = parseInt(req.params.id);
        // TODO: Get campaign from database with email logs
        const campaign = {
            id: campaignId,
            name: 'Q1 Review Campaign',
            status: 'SENT',
            totalEmails: 150,
            sentEmails: 148,
            failedEmails: 2,
            sentAt: new Date('2024-03-15'),
            createdAt: new Date('2024-03-14'),
            emailLogs: [
                {
                    customerEmail: 'customer@example.com',
                    customerName: 'John Doe',
                    status: 'DELIVERED',
                    sentAt: new Date('2024-03-15T10:00:00Z'),
                    openedAt: new Date('2024-03-15T11:30:00Z')
                }
            ]
        };
        res.json({
            success: true,
            data: campaign
        });
    }
    catch (error) {
        logger_1.logger.error('Error fetching campaign:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch campaign'
        });
    }
});
// DELETE /api/campaigns/:id - Delete a campaign
router.delete('/:id', auth_1.authenticateToken, async (req, res) => {
    try {
        const campaignId = parseInt(req.params.id);
        // TODO: Delete campaign from database
        // await db.campaign.delete({ where: { id: campaignId } });
        res.json({
            success: true,
            message: 'Campaign deleted successfully'
        });
    }
    catch (error) {
        logger_1.logger.error('Error deleting campaign:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete campaign'
        });
    }
});
exports.default = router;
//# sourceMappingURL=campaigns.js.map
```

## dist/types/database.js
```javascript
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SubscriptionStatus = exports.SubscriptionPlan = exports.EmailStatus = exports.CampaignStatus = void 0;
var CampaignStatus;
(function (CampaignStatus) {
    CampaignStatus["DRAFT"] = "DRAFT";
    CampaignStatus["SCHEDULED"] = "SCHEDULED";
    CampaignStatus["SENDING"] = "SENDING";
    CampaignStatus["SENT"] = "SENT";
    CampaignStatus["FAILED"] = "FAILED";
})(CampaignStatus || (exports.CampaignStatus = CampaignStatus = {}));
var EmailStatus;
(function (EmailStatus) {
    EmailStatus["SENT"] = "SENT";
    EmailStatus["DELIVERED"] = "DELIVERED";
    EmailStatus["FAILED"] = "FAILED";
    EmailStatus["OPENED"] = "OPENED";
    EmailStatus["CLICKED"] = "CLICKED";
    EmailStatus["BOUNCED"] = "BOUNCED";
    EmailStatus["SPAM"] = "SPAM";
})(EmailStatus || (exports.EmailStatus = EmailStatus = {}));
var SubscriptionPlan;
(function (SubscriptionPlan) {
    SubscriptionPlan["STARTER"] = "STARTER";
    SubscriptionPlan["GROWTH"] = "GROWTH";
    SubscriptionPlan["PRO"] = "PRO";
    SubscriptionPlan["ENTERPRISE"] = "ENTERPRISE";
})(SubscriptionPlan || (exports.SubscriptionPlan = SubscriptionPlan = {}));
var SubscriptionStatus;
(function (SubscriptionStatus) {
    SubscriptionStatus["ACTIVE"] = "ACTIVE";
    SubscriptionStatus["CANCELED"] = "CANCELED";
    SubscriptionStatus["PAST_DUE"] = "PAST_DUE";
    SubscriptionStatus["UNPAID"] = "UNPAID";
})(SubscriptionStatus || (exports.SubscriptionStatus = SubscriptionStatus = {}));
//# sourceMappingURL=database.js.map
```

## dist/services/emailService.js
```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailService = void 0;
// src/services/emailService.ts
const mail_1 = __importDefault(require("@sendgrid/mail"));
const environment_1 = require("../config/environment");
const logger_1 = require("../utils/logger");
mail_1.default.setApiKey(environment_1.config.sendgrid.apiKey);
class EmailService {
    async sendReviewRequestEmails(customers, company, template) {
        const results = [];
        for (const customer of customers) {
            try {
                const personalizedTemplate = this.personalizeTemplate(template, customer, company);
                const msg = {
                    to: customer.email,
                    from: {
                        email: company.fromEmail,
                        name: company.name
                    },
                    subject: personalizedTemplate.subject,
                    html: personalizedTemplate.html,
                    trackingSettings: {
                        clickTracking: { enable: true, enableText: false },
                        openTracking: { enable: true }
                    },
                    // Add custom args for tracking
                    customArgs: {
                        companyId: company.id.toString(),
                        templateId: template.id.toString(),
                        customerEmail: customer.email
                    }
                };
                const response = await mail_1.default.send(msg);
                results.push({
                    success: true,
                    messageId: response[0].headers['x-message-id'],
                    customer
                });
                // Log successful send
                await this.logEmail({
                    companyId: company.id,
                    templateId: template.id,
                    customerEmail: customer.email,
                    customerName: customer.name,
                    status: 'sent',
                    messageId: response[0].headers['x-message-id']
                });
                logger_1.logger.info(`Email sent successfully to ${customer.email}`);
                // Add small delay to avoid rate limiting
                await this.delay(100);
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                results.push({
                    success: false,
                    error: errorMessage,
                    customer
                });
                // Log failed send
                await this.logEmail({
                    companyId: company.id,
                    templateId: template.id,
                    customerEmail: customer.email,
                    customerName: customer.name,
                    status: 'failed',
                    error: errorMessage
                });
                logger_1.logger.error(`Failed to send email to ${customer.email}:`, error);
            }
        }
        return results;
    }
    personalizeTemplate(template, customer, company) {
        const variables = {
            customerName: customer.name,
            companyName: company.name,
            trustpilotLink: company.trustpilotUrl,
            fromName: company.fromName,
            fromEmail: company.fromEmail,
            ...customer.customFields
        };
        let subject = template.subject;
        let html = template.html;
        // Replace variables in format {{variableName}}
        for (const [key, value] of Object.entries(variables)) {
            const regex = new RegExp(`{{${key}}}`, 'g');
            subject = subject.replace(regex, value || '');
            html = html.replace(regex, value || '');
        }
        return { subject, html };
    }
    async logEmail(logData) {
        // This would integrate with your database
        // For now, we'll just log it
        logger_1.logger.info('Email log:', logData);
        // TODO: Insert into database
        // await db.emailLog.create({ data: logData });
    }
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    // Validate email addresses
    static isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    // Validate customer data
    static validateCustomers(customers) {
        const valid = [];
        const invalid = [];
        for (const customer of customers) {
            if (customer &&
                typeof customer.name === 'string' &&
                typeof customer.email === 'string' &&
                customer.name.trim() &&
                this.isValidEmail(customer.email)) {
                valid.push({
                    name: customer.name.trim(),
                    email: customer.email.toLowerCase().trim(),
                    customFields: customer.customFields || {}
                });
            }
            else {
                invalid.push(customer);
            }
        }
        return { valid, invalid };
    }
}
exports.EmailService = EmailService;
//# sourceMappingURL=emailService.js.map
```

## scripts/setup-db.ts
```typescript
import { db, testConnection } from '../src/lib/prisma'

const createTables = async () => {
  try {
    console.log('🔄 Setting up database tables...')

    // Test connection first
    const isConnected = await testConnection()
    if (!isConnected) {
      throw new Error('Could not connect to database')
    }

    // Enable UUID extension
    await db.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    console.log('✅ UUID extension enabled')

    // Create users table
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          email VARCHAR(255) UNIQUE NOT NULL,
          name VARCHAR(255),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Users table created')

    // Create campaigns table
    await db.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          name VARCHAR(255) NOT NULL,
          description TEXT,
          status VARCHAR(50) DEFAULT 'draft',
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Campaigns table created')

    // Create emails table
    await db.query(`
      CREATE TABLE IF NOT EXISTS emails (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          to_email VARCHAR(255) NOT NULL,
          subject VARCHAR(500) NOT NULL,
          content TEXT NOT NULL,
          status VARCHAR(50) DEFAULT 'pending',
          sent_at TIMESTAMP WITH TIME ZONE,
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Emails table created')

    // Create indexes
    await db.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_campaign_id ON emails(campaign_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status)')
    console.log('✅ Indexes created')

    console.log('🎉 Database setup complete!')

  } catch (error) {
    console.error('❌ Database setup failed:', error)
    process.exit(1)
  } finally {
    await db.end()
  }
}

createTables()
```

## scripts/debug-db.ts
```typescript
import { db } from '../src/lib/prisma'

const debugDatabase = async () => {
  try {
    console.log('🔍 Checking database structure...')

    // Check what tables exist
    const tables = await db.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `)
    console.log('📋 Existing tables:', tables.rows.map(r => r.table_name))

    // Check emails table structure if it exists
    if (tables.rows.some(r => r.table_name === 'emails')) {
      const emailsStructure = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'emails'
        ORDER BY ordinal_position
      `)
      console.log('📝 Emails table structure:')
      emailsStructure.rows.forEach(row => {
        console.log(`  - ${row.column_name}: ${row.data_type}`)
      })
    }

    // Check campaigns table structure if it exists
    if (tables.rows.some(r => r.table_name === 'campaigns')) {
      const campaignsStructure = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'campaigns'
        ORDER BY ordinal_position
      `)
      console.log('📝 Campaigns table structure:')
      campaignsStructure.rows.forEach(row => {
        console.log(`  - ${row.column_name}: ${row.data_type}`)
      })
    }

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugDatabase()
```

## scripts/fix-indexes.ts
```typescript
import { db } from '../src/lib/prisma'

const createIndexes = async () => {
  try {
    console.log('🔄 Creating database indexes with correct column names...')

    // Create indexes using the actual column names (camelCase from Prisma)
    await db.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    console.log('✅ Users email index created')

    // Note: using "userId" (camelCase) not "user_id" (snake_case)
    await db.query('CREATE INDEX IF NOT EXISTS idx_campaigns_userId ON campaigns("userId")')
    console.log('✅ Campaigns userId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_userId ON emails("userId")')
    console.log('✅ Emails userId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_campaignId ON emails("campaignId")')
    console.log('✅ Emails campaignId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status)')
    console.log('✅ Emails status index created')

    console.log('🎉 All indexes created successfully!')

  } catch (error) {
    console.error('❌ Index creation failed:', error)
  } finally {
    await db.end()
  }
}

createIndexes()
```

## scripts/debug-emails.ts
```typescript
import { db } from '../src/lib/prisma'

const debugEmails = async () => {
  try {
    console.log('🔍 Checking emails in database...')

    const result = await db.query(`
      SELECT id, "to", status, "userId", "createdAt"
      FROM emails 
      ORDER BY "createdAt" DESC 
      LIMIT 5
    `)

    console.log('📧 Recent emails:')
    result.rows.forEach((email, index) => {
      console.log(`${index + 1}. To: ${email.to}`)
      console.log(`   Status: "${email.status}" (length: ${email.status.length})`)
      console.log(`   UserId: ${email.userId}`)
      console.log(`   Created: ${email.createdAt}`)
      console.log('---')
    })

    console.log('\n📊 Status counts:')
    const statusCounts = await db.query(`
      SELECT status, COUNT(*) as count 
      FROM emails 
      GROUP BY status
    `)
    statusCounts.rows.forEach(row => {
      console.log(`"${row.status}": ${row.count}`)
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugEmails()
```

## scripts/debug-auth.ts
```typescript
import { db } from '../src/lib/prisma'

const debugAuth = async () => {
  try {
    console.log('🔍 Checking users in database...')

    const result = await db.query(`
      SELECT id, email, name, "createdAt"
      FROM users 
      ORDER BY "createdAt" DESC
    `)

    console.log('👥 All users in database:')
    result.rows.forEach((user, index) => {
      console.log(`${index + 1}. ID: ${user.id} (type: ${typeof user.id})`)
      console.log(`   Email: ${user.email}`)
      console.log(`   Name: ${user.name}`)
      console.log(`   Created: ${user.createdAt}`)
      console.log('---')
    })

    console.log('\n📧 Emails and their user associations:')
    const emailsResult = await db.query(`
      SELECT e.id, e."to", e.status, e."userId", u.email as user_email
      FROM emails e
      LEFT JOIN users u ON e."userId" = u.id
      ORDER BY e."createdAt" DESC
    `)

    emailsResult.rows.forEach((email, index) => {
      console.log(`${index + 1}. Email to: ${email.to}`)
      console.log(`   Associated userId: ${email.userId} (type: ${typeof email.userId})`)
      console.log(`   User email: ${email.user_email || 'NO MATCH FOUND'}`)
      console.log('---')
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugAuth()
```

## scripts/create-user-1.ts
```typescript
import { db } from '../src/lib/prisma'

const createUser = async () => {
  try {
    await db.query(`
      INSERT INTO users (id, email, name, "createdAt", "updatedAt")
      VALUES ('1', 'admin@test.com', 'Admin User', NOW(), NOW())
      ON CONFLICT (email) DO NOTHING
    `)
    console.log('✅ User with ID 1 created')
    
    // Verify the user was created
    const result = await db.query('SELECT id, email, name FROM users WHERE id = $1', ['1'])
    if (result.rows.length > 0) {
      console.log('✅ Verified user:', result.rows[0])
    }
    
  } catch (error) {
    console.error('❌ Error:', error)
  } finally {
    await db.end()
  }
}

createUser()

```

## scripts/debug-recent-activity.ts
```typescript
// scripts/debug-recent-activity.ts
import { db } from '../src/lib/prisma'

const debugRecentActivity = async () => {
  try {
    console.log('🔍 Debugging Recent Activity...')

    // Check all emails in database
    const allEmails = await db.query(`
      SELECT 
        id, 
        "to", 
        subject, 
        content, 
        status, 
        "userId", 
        "createdAt"
      FROM emails 
      ORDER BY "createdAt" DESC 
      LIMIT 10
    `)

    console.log(`📧 Found ${allEmails.rows.length} emails total:`)
    allEmails.rows.forEach((email, index) => {
      console.log(`${index + 1}. To: ${email.to}`)
      console.log(`   Subject: "${email.subject}"`)
      console.log(`   Content: "${email.content}"`)
      console.log(`   Status: "${email.status}"`)
      console.log(`   UserId: "${email.userId}" (type: ${typeof email.userId})`)
      console.log(`   Created: ${email.createdAt}`)
      console.log('   ---')
    })

    // Check what user ID the analytics is looking for
    console.log('\n🔍 Testing analytics query with different user IDs...')

    // Test with string '1'
    const stringResult = await db.query(`
      SELECT COUNT(*) as count
      FROM emails 
      WHERE "userId" = $1
    `, ['1'])
    console.log(`String '1': ${stringResult.rows[0].count} emails`)

    // Test with number 1
    const numberResult = await db.query(`
      SELECT COUNT(*) as count
      FROM emails 
      WHERE "userId" = $1
    `, [1])
    console.log(`Number 1: ${numberResult.rows[0].count} emails`)

    // Check users table
    const users = await db.query(`SELECT id, email FROM users LIMIT 5`)
    console.log('\n👥 Users in database:')
    users.rows.forEach(user => {
      console.log(`- ID: "${user.id}" (type: ${typeof user.id}), Email: ${user.email}`)
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugRecentActivity()
```

## app/components/EmailSettingsComponent.tsx
```typescript
'use client';

import { useState, useEffect } from 'react';

interface EmailSettings {
  displayName: string;
  fromEmail: string;
}

export default function EmailSettingsComponent() {
  const [settings, setSettings] = useState<EmailSettings>({
    displayName: '',
    fromEmail: 'charlie.gilbert@ransomspares.co.uk'
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [isEditing, setIsEditing] = useState(false);

  // Load existing settings when component mounts
  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;

      const response = await fetch(`${apiUrl}/api/user/email-settings`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      const result = await response.json();

      if (result.success) {
        setSettings(result.data);
      }
    } catch (error) {
      console.error('Error loading settings:', error);
      // Set default from user data if available
      const userData = localStorage.getItem('user');
      if (userData) {
        const user = JSON.parse(userData);
        setSettings(prev => ({
          ...prev,
          displayName: `${user.firstName} ${user.lastName}`
        }));
      }
    }
  };

  const handleSave = async () => {
    if (!settings.displayName.trim()) {
      setMessage('❌ Display name is required');
      return;
    }

    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;

      const response = await fetch(`${apiUrl}/api/user/email-settings`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          displayName: settings.displayName.trim()
        }),
      });

      const result = await response.json();

      if (result.success) {
        setMessage('✅ Email settings saved successfully!');
        setIsEditing(false);
      } else {
        setMessage(`❌ Error: ${result.error}`);
      }
    } catch (error) {
      setMessage('❌ Failed to save settings');
      console.error('Save settings error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    setIsEditing(false);
    loadSettings(); // Reload original settings
    setMessage('');
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <div className="p-6 border-b border-gray-200">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-lg font-medium text-gray-900">Email Settings</h3>
            <p className="text-sm text-gray-500 mt-1">Configure how your emails appear to customers</p>
          </div>
          {!isEditing && (
            <button
              onClick={() => setIsEditing(true)}
              className="px-4 py-2 text-sm font-medium text-blue-600 hover:text-blue-700 border border-blue-600 rounded-md hover:bg-blue-50 transition-colors"
            >
              Edit Settings
            </button>
          )}
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Display Name Setting */}
        <div>
          <label htmlFor="displayName" className="block text-sm font-medium text-gray-700 mb-2">
            Display Name
          </label>
          <p className="text-xs text-gray-500 mb-3">
            This is how your name appears to customers when they receive review request emails
          </p>
          {isEditing ? (
            <input
              type="text"
              id="displayName"
              value={settings.displayName}
              onChange={(e) => setSettings({...settings, displayName: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="e.g., Charlie Gilbert"
              maxLength={50}
            />
          ) : (
            <div className="px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-gray-900">
              {settings.displayName || 'Not set'}
            </div>
          )}
        </div>

        {/* From Email (Read-only for now) */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            From Email Address
          </label>
          <p className="text-xs text-gray-500 mb-3">
            All emails will be sent from this authenticated address
          </p>
          <div className="px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-gray-700">
            {settings.fromEmail}
            <span className="ml-2 text-xs text-green-600 font-medium">✓ Verified</span>
          </div>
        </div>

        {/* Preview Section */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-blue-900 mb-2">Email Preview</h4>
          <p className="text-sm text-blue-700">
            Customers will see: <strong>"{settings.displayName || 'Your Name'} &lt;{settings.fromEmail}&gt;"</strong>
          </p>
        </div>

        {/* Action Buttons */}
        {isEditing && (
          <div className="flex space-x-3 pt-4 border-t border-gray-200">
            <button
              onClick={handleSave}
              disabled={loading}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
            >
              {loading ? 'Saving...' : 'Save Settings'}
            </button>
            <button
              onClick={handleCancel}
              disabled={loading}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors text-sm font-medium"
            >
              Cancel
            </button>
          </div>
        )}

        {/* Message Display */}
        {message && (
          <div className={`p-3 rounded-lg text-sm ${
            message.includes('✅')
              ? 'bg-green-50 text-green-700 border border-green-200'
              : 'bg-red-50 text-red-700 border border-red-200'
          }`}>
            {message}
          </div>
        )}
      </div>
    </div>
  );
}
```
