import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { AppRequest } from '@app/core/types/app-request';
import {
	Injectable,
	NestMiddleware,
	UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { FastifyReply } from 'fastify';

@Injectable()
export class ApiKeyValidationMiddleware implements NestMiddleware {
	constructor(private prisma: PrismaService) {}

	async use(req: AppRequest, _res: FastifyReply, next: () => void) {
		const apiKey = req.headers['x-api-key'] as string | undefined;

		if (!apiKey) {
			throw new UnauthorizedException('Missing X-API-KEY header');
		}

		try {
			// Fetch all API keys and compare hashes
			const allKeys = await this.prisma.apiKey.findMany({
				select: { id: true, keyHash: true, application: true },
			});

			let validKey: {
				id: string;
				keyHash: string;
				application: string;
			} | null = null;
			for (const k of allKeys) {
				if (await bcrypt.compare(apiKey, k.keyHash)) {
					validKey = k;
					break;
				}
			}

			if (!validKey) {
				throw new UnauthorizedException('Invalid API Key');
			}

			// Adjuntar info del API key al request si se necesita en el futuro
			req.apiKey = validKey;

			next();
		} catch (_error) {
			throw new UnauthorizedException('Invalid API Key');
		}
	}
}
