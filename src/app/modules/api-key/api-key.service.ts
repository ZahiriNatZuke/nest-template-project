import { randomBytes } from 'node:crypto';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateApiKeyZodDto } from '@app/modules/api-key/dto/create-api-key.dto';
import { Injectable } from '@nestjs/common';
import { ApiKey, Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { z } from 'zod';

@Injectable()
export class ApiKeyService {
	constructor(private prisma: PrismaService) {}

	async findMany() {
		return this.prisma.apiKey.findMany({
			select: {
				id: true,
				application: true,
				default: true,
				createdAt: true,
				updatedAt: true,
			},
		});
	}

	async findOne(
		apiKeyWhereUniqueInput: Prisma.ApiKeyWhereUniqueInput,
		canThrow = false
	) {
		if (canThrow) {
			return this.prisma.apiKey.findUniqueOrThrow({
				where: apiKeyWhereUniqueInput,
				select: {
					id: true,
					application: true,
					default: true,
					createdAt: true,
					updatedAt: true,
				},
			});
		}

		return this.prisma.apiKey.findUnique({
			where: apiKeyWhereUniqueInput,
			select: {
				id: true,
				application: true,
				default: true,
				createdAt: true,
				updatedAt: true,
			},
		});
	}

	async create({ application }: CreateApiKeyZodDto): Promise<{
		apiKey: Omit<ApiKey, 'keyHash'>;
		plainKey: string;
	}> {
		try {
			const plainKey = randomBytes(64).toString('base64');
			const keyHash = await bcrypt.hash(plainKey, bcrypt.genSaltSync(12));

			const apiKey = await this.prisma.apiKey.create({
				data: {
					application,
					keyHash,
				},
				select: {
					id: true,
					application: true,
					default: true,
					createdAt: true,
					updatedAt: true,
				},
			});

			// Return plain key ONLY on creation (one-time reveal)
			return { apiKey, plainKey };
		} catch (_e) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Create api key failure',
					},
				])
			);
		}
	}

	async validateApiKey(plainKey: string): Promise<boolean> {
		const allKeys = await this.prisma.apiKey.findMany({
			select: { keyHash: true },
		});

		for (const k of allKeys) {
			if (await bcrypt.compare(plainKey, k.keyHash)) {
				return true;
			}
		}
		return false;
	}

	async delete(where: Prisma.ApiKeyWhereUniqueInput): Promise<ApiKey> {
		return this.prisma.apiKey.delete({ where });
	}
}
