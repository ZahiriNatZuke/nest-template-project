import { PrismaService } from '@app/core/services/prisma/prisma.service';
import {
	HealthCheckService,
	MemoryHealthIndicator,
	PrismaHealthIndicator,
} from '@nestjs/terminus';
import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from './health.controller';

describe('HealthController', () => {
	let controller: HealthController;
	let healthCheckService: HealthCheckService;
	let prismaHealthIndicator: PrismaHealthIndicator;
	let memoryHealthIndicator: MemoryHealthIndicator;

	const mockHealthCheckService = {
		check: jest.fn(),
	};

	const mockPrismaHealthIndicator = {
		pingCheck: jest.fn(),
	};

	const mockMemoryHealthIndicator = {
		checkHeap: jest.fn(),
		checkRSS: jest.fn(),
	};

	const mockPrismaService = {
		$queryRaw: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			controllers: [HealthController],
			providers: [
				{
					provide: HealthCheckService,
					useValue: mockHealthCheckService,
				},
				{
					provide: PrismaHealthIndicator,
					useValue: mockPrismaHealthIndicator,
				},
				{
					provide: MemoryHealthIndicator,
					useValue: mockMemoryHealthIndicator,
				},
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		controller = module.get<HealthController>(HealthController);
		healthCheckService = module.get<HealthCheckService>(HealthCheckService);
		prismaHealthIndicator = module.get<PrismaHealthIndicator>(
			PrismaHealthIndicator
		);
		memoryHealthIndicator = module.get<MemoryHealthIndicator>(
			MemoryHealthIndicator
		);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(controller).toBeDefined();
	});

	describe('check()', () => {
		it('should return healthy status when all checks pass', async () => {
			const healthyResult = {
				status: 'ok',
				info: {
					database: { status: 'up' },
					memory_heap: { status: 'up' },
					memory_rss: { status: 'up' },
				},
				error: {},
				details: {
					database: { status: 'up' },
					memory_heap: { status: 'up' },
					memory_rss: { status: 'up' },
				},
			};

			mockHealthCheckService.check.mockResolvedValue(healthyResult);

			const result = await controller.check();

			expect(result).toEqual(healthyResult);
			expect(result.status).toBe('ok');
			expect(healthCheckService.check).toHaveBeenCalledWith(
				expect.arrayContaining([expect.any(Function)])
			);
			expect(healthCheckService.check).toHaveBeenCalledTimes(1);
		});

		it('should call all health indicators', async () => {
			mockHealthCheckService.check.mockImplementation(async checks => {
				// Execute all check functions
				for (const check of checks) {
					await check();
				}
				return {
					status: 'ok',
					info: {},
					error: {},
					details: {},
				};
			});

			mockPrismaHealthIndicator.pingCheck.mockResolvedValue({
				database: { status: 'up' },
			});
			mockMemoryHealthIndicator.checkHeap.mockResolvedValue({
				memory_heap: { status: 'up' },
			});
			mockMemoryHealthIndicator.checkRSS.mockResolvedValue({
				memory_rss: { status: 'up' },
			});

			await controller.check();

			expect(prismaHealthIndicator.pingCheck).toHaveBeenCalledWith(
				'database',
				mockPrismaService
			);
			expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith(
				'memory_heap',
				150 * 1024 * 1024
			);
			expect(memoryHealthIndicator.checkRSS).toHaveBeenCalledWith(
				'memory_rss',
				300 * 1024 * 1024
			);
		});

		it('should return error status when a check fails', async () => {
			const unhealthyResult = {
				status: 'error',
				info: {
					memory_heap: { status: 'up' },
					memory_rss: { status: 'up' },
				},
				error: {
					database: { status: 'down', message: 'Connection failed' },
				},
				details: {
					database: { status: 'down', message: 'Connection failed' },
					memory_heap: { status: 'up' },
					memory_rss: { status: 'up' },
				},
			};

			mockHealthCheckService.check.mockResolvedValue(unhealthyResult);

			const result = await controller.check();

			expect(result.status).toBe('error');
			expect(result.error).toBeDefined();
		});
	});

	describe('ready()', () => {
		it('should return ready status when database is connected', async () => {
			const readyResult = {
				status: 'ok',
				info: {
					database: { status: 'up' },
				},
				error: {},
				details: {
					database: { status: 'up' },
				},
			};

			mockHealthCheckService.check.mockResolvedValue(readyResult);

			const result = await controller.ready();

			expect(result).toEqual(readyResult);
			expect(result.status).toBe('ok');
			expect(healthCheckService.check).toHaveBeenCalledWith(
				expect.arrayContaining([expect.any(Function)])
			);
		});

		it('should only check database connectivity', async () => {
			mockHealthCheckService.check.mockImplementation(async checks => {
				// Verify only 1 check is passed
				expect(checks).toHaveLength(1);

				// Execute the check
				await checks[0]();

				return {
					status: 'ok',
					info: {},
					error: {},
					details: {},
				};
			});

			mockPrismaHealthIndicator.pingCheck.mockResolvedValue({
				database: { status: 'up' },
			});

			await controller.ready();

			expect(prismaHealthIndicator.pingCheck).toHaveBeenCalledWith(
				'database',
				mockPrismaService
			);
			// Memory checks should NOT be called
			expect(memoryHealthIndicator.checkHeap).not.toHaveBeenCalled();
			expect(memoryHealthIndicator.checkRSS).not.toHaveBeenCalled();
		});

		it('should return not ready when database is down', async () => {
			const notReadyResult = {
				status: 'error',
				info: {},
				error: {
					database: { status: 'down', message: 'Database unreachable' },
				},
				details: {
					database: { status: 'down', message: 'Database unreachable' },
				},
			};

			mockHealthCheckService.check.mockResolvedValue(notReadyResult);

			const result = await controller.ready();

			expect(result.status).toBe('error');
			expect(result.error).toBeDefined();
		});
	});

	describe('live()', () => {
		it('should return alive status when memory is within limits', async () => {
			const aliveResult = {
				status: 'ok',
				info: {
					memory_heap: { status: 'up' },
				},
				error: {},
				details: {
					memory_heap: { status: 'up' },
				},
			};

			mockHealthCheckService.check.mockResolvedValue(aliveResult);

			const result = await controller.live();

			expect(result).toEqual(aliveResult);
			expect(result.status).toBe('ok');
		});

		it('should only check heap memory', async () => {
			mockHealthCheckService.check.mockImplementation(async checks => {
				// Verify only 1 check is passed
				expect(checks).toHaveLength(1);

				// Execute the check
				await checks[0]();

				return {
					status: 'ok',
					info: {},
					error: {},
					details: {},
				};
			});

			mockMemoryHealthIndicator.checkHeap.mockResolvedValue({
				memory_heap: { status: 'up' },
			});

			await controller.live();

			expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith(
				'memory_heap',
				200 * 1024 * 1024
			);
			// Database and RSS checks should NOT be called
			expect(prismaHealthIndicator.pingCheck).not.toHaveBeenCalled();
			expect(memoryHealthIndicator.checkRSS).not.toHaveBeenCalled();
		});

		it('should return not alive when memory exceeds limit', async () => {
			const notAliveResult = {
				status: 'error',
				info: {},
				error: {
					memory_heap: {
						status: 'down',
						message: 'Heap memory exceeded 200MB',
					},
				},
				details: {
					memory_heap: {
						status: 'down',
						message: 'Heap memory exceeded 200MB',
					},
				},
			};

			mockHealthCheckService.check.mockResolvedValue(notAliveResult);

			const result = await controller.live();

			expect(result.status).toBe('error');
			expect(result.error).toBeDefined();
		});
	});

	describe('Health Indicator Configurations', () => {
		it('should use correct memory limits for full health check', async () => {
			mockHealthCheckService.check.mockImplementation(async checks => {
				for (const check of checks) {
					await check();
				}
				return { status: 'ok', info: {}, error: {}, details: {} };
			});

			mockPrismaHealthIndicator.pingCheck.mockResolvedValue({});
			mockMemoryHealthIndicator.checkHeap.mockResolvedValue({});
			mockMemoryHealthIndicator.checkRSS.mockResolvedValue({});

			await controller.check();

			// Heap limit: 150MB
			expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith(
				'memory_heap',
				150 * 1024 * 1024
			);

			// RSS limit: 300MB
			expect(memoryHealthIndicator.checkRSS).toHaveBeenCalledWith(
				'memory_rss',
				300 * 1024 * 1024
			);
		});

		it('should use higher memory limit for liveness check', async () => {
			mockHealthCheckService.check.mockImplementation(async checks => {
				await checks[0]();
				return { status: 'ok', info: {}, error: {}, details: {} };
			});

			mockMemoryHealthIndicator.checkHeap.mockResolvedValue({});

			await controller.live();

			// Liveness has higher limit (200MB) to avoid false positives
			expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith(
				'memory_heap',
				200 * 1024 * 1024
			);
		});
	});
});
