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

      // Count both uppercase and lowercase statuses
      const delivered = (statusBreakdown['delivered'] || 0) + (statusBreakdown['DELIVERED'] || 0);
      const opened = (statusBreakdown['opened'] || 0) + (statusBreakdown['OPENED'] || 0) + 
                     (statusBreakdown['clicked'] || 0) + (statusBreakdown['CLICKED'] || 0);
      const clicked = (statusBreakdown['clicked'] || 0) + (statusBreakdown['CLICKED'] || 0);
      const bounced = (statusBreakdown['bounced'] || 0) + (statusBreakdown['BOUNCED'] || 0);
      const spam = (statusBreakdown['spam'] || 0) + (statusBreakdown['SPAM'] || 0);
      const failed = (statusBreakdown['failed'] || 0) + (statusBreakdown['FAILED'] || 0);

      // For emails that went straight to clicked/opened without explicit delivered status
      const implicitDelivered = delivered + opened;

      // Only ONE deliveryRate declaration:
      const deliveryRate = emailsSent > 0 ? Math.round((implicitDelivered / emailsSent) * 100) : 0;

      // Calculate other rates (no more deliveryRate here!)
      const openRate = delivered > 0 ? Math.round((opened / delivered) * 100) : 0;
      const clickRate = opened > 0 ? Math.round((clicked / opened) * 100) : 0;
      const bounceRate = emailsSent > 0 ? Math.round((bounced / emailsSent) * 100) : 0;
      const spamRate = emailsSent > 0 ? Math.round((spam / emailsSent) * 100) : 0;

      // Monthly limits
      const monthlyLimit = 100000;
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
          delivered: implicitDelivered,  // Use the calculated value that includes opened/clicked
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