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
            name: company.fromName
          },
          subject: personalizedTemplate.subject,
          html: personalizedTemplate.html,
          asm: {
            groupId: 27196,
            groupsToDisplay: [27196]
          },
          trackingSettings: {
            clickTracking: { enable: true, enableText: false },
            openTracking: { enable: true },
            subscriptionTracking: {
              enable: true,
              text: 'Unsubscribe from review requests',
              html: '<p style="text-align: center; font-size: 11px; color: #666; margin-top: 20px;">Don\'t want to receive review request emails? <a href="<%asm_group_unsubscribe_raw_url%>" style="color: #666; text-decoration: underline;">Unsubscribe here</a></p>'
            }
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
          status: 'SENT',  // Keep uppercase for TypeScript
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
      // Use the actual userId passed from the route
      let userIdString = logData.userId ? logData.userId.toString() : '1';
      console.log(`Saving email with userId: ${userIdString}`);

      // Ensure we have a valid user in the database
      await this.ensureUserExists(userIdString);

      // Create a more descriptive subject line
      const subjectLine = `Review Request for ${logData.customerName}`;
      const contentDescription = `${logData.status} - Email ${logData.status.toLowerCase()} to ${logData.customerName} (${logData.customerEmail})`;

      // Create email log record using direct SQL
      await db.query(`
        INSERT INTO emails (
          "to", subject, content, status, "sentAt", 
          "userId", "campaignId", "sendgridMessageId", "createdAt", "updatedAt"
          ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW()
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

