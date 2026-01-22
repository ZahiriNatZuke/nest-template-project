import { Throttle as NestThrottle } from '@nestjs/throttler';

/**
 * Custom decorator for applying rate limiting to specific endpoints
 * Uses the configured throttler settings from app.module.ts
 */

/**
 * Strict rate limiting for sensitive operations like login
 * 5 requests per minute
 */
export const StrictThrottle = () =>
	NestThrottle({ default: { limit: 5, ttl: 60000 } });

/**
 * Moderate rate limiting for password reset and similar operations
 * 3 requests per 5 minutes
 */
export const ModerateThrottle = () =>
	NestThrottle({ default: { limit: 3, ttl: 300000 } });

/**
 * Lenient rate limiting for general authenticated endpoints
 * 100 requests per minute
 */
export const LenientThrottle = () =>
	NestThrottle({ default: { limit: 100, ttl: 60000 } });

/**
 * Skip rate limiting (use with caution)
 */
export const SkipThrottle = () =>
	NestThrottle({ default: { limit: 0, ttl: 0 } });
