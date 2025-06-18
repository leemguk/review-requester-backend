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
      const userId = authenticatedUser.id;
      logger.info(`Sending emails as user ID: ${userId}, type: ${typeof userId}`);

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
        name: 'Ransom Spares',
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
