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