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