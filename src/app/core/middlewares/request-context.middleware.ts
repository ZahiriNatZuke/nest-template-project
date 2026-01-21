import { extractRequestInfo } from '@app/core/utils/request-info';
import { Injectable, NestMiddleware } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';

export type RequestWithContext = FastifyRequest & {
	requestContext?: { ipAddress?: string; userAgent?: string };
};

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
	use(req: FastifyRequest, _res: FastifyReply, next: () => void) {
		const { ipAddress, userAgent } = extractRequestInfo(req);
		(req as RequestWithContext).requestContext = { ipAddress, userAgent };
		next();
	}
}
