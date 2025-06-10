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