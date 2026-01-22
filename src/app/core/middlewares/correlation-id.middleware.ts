import { Injectable, NestMiddleware } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { v4 as uuidv4 } from 'uuid';

/**
 * Middleware to add correlation ID to every request
 * This ID is used to track requests across services and logs
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
	use(req: FastifyRequest['raw'], res: FastifyReply['raw'], next: () => void) {
		// Check if correlation ID already exists in headers
		const correlationId =
			(req.headers['x-correlation-id'] as string) ||
			(req.headers['x-request-id'] as string) ||
			uuidv4();

		// Store in request for later use
		const requestWithCorrelation = req as FastifyRequest['raw'] & {
			correlationId?: string;
		};
		requestWithCorrelation.correlationId = correlationId;

		// Add to response headers
		res.setHeader('X-Correlation-ID', correlationId);

		next();
	}
}
