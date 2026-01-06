import { envs } from '@app/env';
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
	extends PrismaClient
	implements OnModuleInit, OnModuleDestroy
{
	constructor() {
		const adapter = new PrismaPg({
			connectionString: envs.DATABASE_URL,
		});

		super({
			adapter,
			log: [
				{ emit: 'stdout', level: 'query' },
				{ emit: 'stdout', level: 'info' },
				{ emit: 'stdout', level: 'warn' },
				{ emit: 'stdout', level: 'error' },
			],
		});
	}

	async onModuleInit() {
		await this.$connect();
	}

	async onModuleDestroy() {
		await this.$disconnect();
	}
}
