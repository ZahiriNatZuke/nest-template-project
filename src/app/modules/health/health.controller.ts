import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import {
	HealthCheck,
	type HealthCheckResult,
	HealthCheckService,
	MemoryHealthIndicator,
	PrismaHealthIndicator,
} from '@nestjs/terminus';

@ApiTags('Health')
@Controller('health')
export class HealthController {
	constructor(
		private health: HealthCheckService,
		private db: PrismaHealthIndicator,
		private memory: MemoryHealthIndicator,
		private prisma: PrismaService
	) {}

	@Get()
	@HealthCheck()
	@ApiOperation({
		summary: 'Application Health Check',
		description:
			'Returns the health status of the application including database, memory, and disk usage',
	})
	@ApiResponse({
		status: 200,
		description: 'Application is healthy',
		schema: {
			type: 'object',
			properties: {
				status: { type: 'string', example: 'ok' },
				info: {
					type: 'object',
					properties: {
						database: {
							type: 'object',
							properties: {
								status: { type: 'string', example: 'up' },
							},
						},
						memory_heap: {
							type: 'object',
							properties: {
								status: { type: 'string', example: 'up' },
							},
						},
						memory_rss: {
							type: 'object',
							properties: {
								status: { type: 'string', example: 'up' },
							},
						},
					},
				},
				error: { type: 'object' },
				details: { type: 'object' },
			},
		},
	})
	@ApiResponse({
		status: 503,
		description: 'Application is unhealthy',
	})
	async check(): Promise<HealthCheckResult> {
		return this.health.check([
			// Database Health Check
			() => this.db.pingCheck('database', this.prisma),

			// Memory Health Checks
			// Heap should not exceed 150MB
			() => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),

			// RSS (Resident Set Size) should not exceed 300MB
			() => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),
		]);
	}

	@Get('ready')
	@HealthCheck()
	@ApiOperation({
		summary: 'Readiness Probe',
		description:
			'Checks if the application is ready to accept traffic (database connection)',
	})
	@ApiResponse({
		status: 200,
		description: 'Application is ready',
	})
	@ApiResponse({
		status: 503,
		description: 'Application is not ready',
	})
	async ready(): Promise<HealthCheckResult> {
		return this.health.check([
			// Only check database connectivity
			() => this.db.pingCheck('database', this.prisma),
		]);
	}

	@Get('live')
	@HealthCheck()
	@ApiOperation({
		summary: 'Liveness Probe',
		description:
			'Checks if the application is alive (basic memory check, lighter than full health check)',
	})
	@ApiResponse({
		status: 200,
		description: 'Application is alive',
	})
	@ApiResponse({
		status: 503,
		description: 'Application is not responding',
	})
	async live(): Promise<HealthCheckResult> {
		return this.health.check([
			// Only check memory to ensure app is responsive
			() => this.memory.checkHeap('memory_heap', 200 * 1024 * 1024),
		]);
	}
}
