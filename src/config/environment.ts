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