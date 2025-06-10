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