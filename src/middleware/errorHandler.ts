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