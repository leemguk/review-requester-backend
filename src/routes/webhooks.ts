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
    // Try to find by SendGrid message ID first (more accurate)
    let emailResult;
    if (event.sg_message_id) {
      emailResult = await db.query(`
        SELECT id, "userId", "to", status, "createdAt"
        FROM emails 
        WHERE "sendgridMessageId" = $1
        LIMIT 1
      `, [event.sg_message_id.split('.')[0]]); // SendGrid adds .filter after ID
    }

    // Fallback to email address if no message ID match
    if (!emailResult || emailResult.rows.length === 0) {
      emailResult = await db.query(`
        SELECT id, "userId", "to", status, "createdAt"
        FROM emails 
        WHERE "to" = $1
        ORDER BY "createdAt" DESC
        LIMIT 1
      `, [customerEmail]);
    }

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
            updateParams = ['delivered', emailId, timestamp];  // <-- Change 'DELIVERED' to 'delivered'
            break;
          case 'open':
            updateQuery = `UPDATE emails SET status = $1, "openedAt" = $3, "openCount" = COALESCE("openCount", 0) + 1, "updatedAt" = NOW() WHERE id = $2`;
            updateParams = ['opened', emailId, timestamp];  // <-- Change 'OPENED' to 'opened'
            break;
          case 'click':
            updateQuery = `UPDATE emails SET status = $1, "clickedAt" = $3, "clickCount" = COALESCE("clickCount", 0) + 1, "updatedAt" = NOW() WHERE id = $2`;
            updateParams = ['clicked', emailId, timestamp];  // <-- Change 'CLICKED' to 'clicked'
            break;
          case 'bounce':
          case 'dropped':
            updateQuery = `UPDATE emails SET status = $1, "bouncedAt" = $3, "updatedAt" = NOW() WHERE id = $2`;
            updateParams = ['bounced', emailId, timestamp];  // <-- Change 'BOUNCED' to 'bounced'
            break;
          case 'spamreport':
            updateQuery = `UPDATE emails SET status = $1, "spamAt" = $3, "updatedAt" = NOW() WHERE id = $2`;
            updateParams = ['spam', emailId, timestamp];  // <-- Change 'SPAM' to 'spam'
            break;
      case 'processed':
        return true; // Acknowledge silently
      default:
        return true; // Unknown events, ignore silently
    }

    const result = await db.query(updateQuery, updateParams);
   return (result.rowCount || 0) > 0;

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