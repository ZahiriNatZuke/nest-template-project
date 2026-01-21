import { LoginAttemptService } from '@app/core/services/login-attempt/login-attempt.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import type { SafeUser } from '@app/core/types/app-request';
import { ModuleRef } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import type { User } from '@prisma/client';
import { UserMapper } from '../user/user.mapper';
import { AuthService } from './auth.service';

describe('AuthService', () => {
	let service: AuthService;

	const mockPrismaService = {
		user: {
			findUniqueOrThrow: jest.fn(),
			update: jest.fn(),
		},
		session: {
			findUnique: jest.fn(),
			findFirst: jest.fn(),
			findMany: jest.fn(),
			count: jest.fn(),
			create: jest.fn(),
			update: jest.fn(),
			delete: jest.fn(),
			deleteMany: jest.fn(),
		},
		tokenBlacklist: {
			create: jest.fn(),
			findUnique: jest.fn(),
		},
		userRole: {
			findMany: jest.fn(),
		},
	};

	const mockJwtService = {
		sign: jest.fn(),
	};

	const mockUserMapper = {
		omitDefault: jest.fn(user => user),
	};

	const mockModuleRef = {
		get: jest.fn(),
	};

	const mockLoginAttemptService = {
		validateLoginAttempt: jest.fn(),
		recordSuccessfulAttempt: jest.fn(),
		recordFailedAttempt: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				AuthService,
				{ provide: PrismaService, useValue: mockPrismaService },
				{ provide: JwtService, useValue: mockJwtService },
				{ provide: UserMapper, useValue: mockUserMapper },
				{ provide: ModuleRef, useValue: mockModuleRef },
				{ provide: LoginAttemptService, useValue: mockLoginAttemptService },
			],
		}).compile();

		service = module.get<AuthService>(AuthService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('generateSession - Concurrent Sessions Limit', () => {
		const mockUser: SafeUser = {
			id: 'user-1',
			email: 'test@test.com',
			username: 'testuser',
			fullName: 'Test User',
			confirmed: true,
			blocked: false,
			createdAt: new Date(),
			updatedAt: new Date(),
			confirmedAt: new Date(),
			avatarUrl: 'http://example.com/avatar.png',
			phone: '1234567890',
			address: '123 Test St',
			bio: 'This is a test user.',
		};

		const mockUserRoles = [
			{
				role: {
					rolePermissions: [
						{ permission: { identifier: 'read:users' } },
						{ permission: { identifier: 'write:users' } },
					],
				},
			},
		];

		beforeEach(() => {
			mockPrismaService.userRole.findMany.mockResolvedValue(mockUserRoles);
			mockJwtService.sign.mockReturnValue('mock-token');
		});

		it('should create new session when under limit', async () => {
			// Simular que no hay sesión existente para este device
			mockPrismaService.session.findUnique.mockResolvedValue(null);
			// Simular que el usuario tiene 2 sesiones activas (bajo el límite de 5)
			mockPrismaService.session.count.mockResolvedValue(2);
			mockPrismaService.session.create.mockResolvedValue({
				id: 'session-1',
				userId: mockUser.id,
				device: 'web',
				accessToken: 'mock-token',
				refreshToken: 'mock-refresh',
			});

			const result = await service.generateSession(
				mockUser,
				'web',
				'192.168.1.1',
				'Mozilla/5.0'
			);

			expect(mockPrismaService.session.count).toHaveBeenCalledWith({
				where: { userId: mockUser.id },
			});
			expect(mockPrismaService.session.create).toHaveBeenCalled();
			expect(result).toBeDefined();
			expect(result.device).toBe('web');
		});

		it('should remove oldest session when at limit', async () => {
			const oldestSession = {
				id: 'old-session',
				userId: mockUser.id,
				device: 'mobile-old',
				accessToken: 'old-access-token',
				refreshToken: 'old-refresh-token',
				createdAt: new Date('2024-01-01'),
			};

			// Simular que no hay sesión existente para este device
			mockPrismaService.session.findUnique.mockResolvedValue(null);
			// Simular que el usuario ya tiene 5 sesiones (límite alcanzado)
			mockPrismaService.session.count.mockResolvedValue(5);
			// Simular encontrar la sesión más antigua
			mockPrismaService.session.findFirst.mockResolvedValue(oldestSession);
			mockPrismaService.session.delete.mockResolvedValue(oldestSession);
			mockPrismaService.tokenBlacklist.create.mockResolvedValue({});
			mockPrismaService.session.create.mockResolvedValue({
				id: 'new-session',
				userId: mockUser.id,
				device: 'web-new',
				accessToken: 'new-token',
				refreshToken: 'new-refresh',
			});

			await service.generateSession(
				mockUser,
				'web-new',
				'192.168.1.1',
				'Mozilla/5.0'
			);

			// Verificar que se buscó la sesión más antigua
			expect(mockPrismaService.session.findFirst).toHaveBeenCalledWith({
				where: { userId: mockUser.id },
				orderBy: { createdAt: 'asc' },
			});

			// Verificar que se agregaron los tokens viejos a blacklist
			expect(mockPrismaService.tokenBlacklist.create).toHaveBeenCalledTimes(2);

			// Verificar que se eliminó la sesión antigua
			expect(mockPrismaService.session.delete).toHaveBeenCalledWith({
				where: { id: oldestSession.id },
			});

			// Verificar que se creó la nueva sesión
			expect(mockPrismaService.session.create).toHaveBeenCalled();
		});

		it('should update existing session for same device', async () => {
			const existingSession = {
				id: 'existing-session',
				userId: mockUser.id,
				device: 'web',
				accessToken: 'old-token',
				refreshToken: 'old-refresh',
			};

			// Simular que ya existe una sesión para este device
			mockPrismaService.session.findUnique.mockResolvedValue(existingSession);
			mockPrismaService.tokenBlacklist.create.mockResolvedValue({});
			mockPrismaService.session.update.mockResolvedValue({
				...existingSession,
				accessToken: 'new-token',
				refreshToken: 'new-refresh',
			});

			await service.generateSession(
				mockUser,
				'web',
				'192.168.1.1',
				'Mozilla/5.0'
			);

			// No debe verificar el límite si actualiza sesión existente
			expect(mockPrismaService.session.count).not.toHaveBeenCalled();
			// Debe actualizar la sesión existente
			expect(mockPrismaService.session.update).toHaveBeenCalled();
			// No debe eliminar sesiones antiguas
			expect(mockPrismaService.session.delete).not.toHaveBeenCalled();
		});
	});

	describe('updatePassword - Session Revocation', () => {
		const mockUser = {
			id: 'user-1',
			email: 'test@test.com',
			password: '$2b$16$hashedPassword', // bcrypt hash de "OldPass123!"
		} as User;

		it('should invalidate all sessions on password change', async () => {
			const sessions = [
				{
					id: 'session-1',
					accessToken: 'token-1',
					refreshToken: 'refresh-1',
				},
				{
					id: 'session-2',
					accessToken: 'token-2',
					refreshToken: 'refresh-2',
				},
			];

			mockPrismaService.user.findUniqueOrThrow.mockResolvedValue(mockUser);
			mockPrismaService.session.findMany.mockResolvedValue(sessions);
			mockPrismaService.tokenBlacklist.create.mockResolvedValue({});
			mockPrismaService.session.deleteMany.mockResolvedValue({ count: 2 });
			mockPrismaService.user.update.mockResolvedValue({
				...mockUser,
				password: 'new-hash',
			});

			// Mock bcrypt.compare para current password
			const bcrypt = require('bcrypt');
			jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
			jest.spyOn(bcrypt, 'hash').mockResolvedValue('new-hash');

			await service.updatePassword(
				{
					current_password: 'OldPass123!',
					new_password: 'NewPass456!',
					confirm_new_password: 'NewPass456!',
				},
				mockUser
			);

			// Verificar que se obtuvieron todas las sesiones
			expect(mockPrismaService.session.findMany).toHaveBeenCalledWith({
				where: { userId: mockUser.id },
			});

			// Verificar que se agregaron TODOS los tokens a blacklist (2 sesiones x 2 tokens = 4)
			expect(mockPrismaService.tokenBlacklist.create).toHaveBeenCalledTimes(4);

			// Verificar que se eliminaron TODAS las sesiones
			expect(mockPrismaService.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: mockUser.id },
			});

			// Verificar que se actualizó la contraseña
			expect(mockPrismaService.user.update).toHaveBeenCalledWith({
				where: { id: mockUser.id },
				data: { password: 'new-hash' },
			});
		});
	});

	describe('invalidateAllUserSessions', () => {
		it('should blacklist all tokens and delete all sessions', async () => {
			const userId = 'user-1';
			const sessions = [
				{
					id: 'session-1',
					accessToken: 'access-1',
					refreshToken: 'refresh-1',
				},
				{
					id: 'session-2',
					accessToken: 'access-2',
					refreshToken: 'refresh-2',
				},
				{
					id: 'session-3',
					accessToken: 'access-3',
					refreshToken: 'refresh-3',
				},
			];

			mockPrismaService.session.findMany.mockResolvedValue(sessions);
			mockPrismaService.tokenBlacklist.create.mockResolvedValue({});
			mockPrismaService.session.deleteMany.mockResolvedValue({ count: 3 });

			await service.invalidateAllUserSessions(userId);

			// Debe haber creado 6 entradas en blacklist (3 sesiones x 2 tokens)
			expect(mockPrismaService.tokenBlacklist.create).toHaveBeenCalledTimes(6);

			// Verificar que se llamó con los tokens correctos
			expect(mockPrismaService.tokenBlacklist.create).toHaveBeenCalledWith(
				expect.objectContaining({
					data: expect.objectContaining({
						token: 'access-1',
					}),
				})
			);

			// Debe eliminar todas las sesiones
			expect(mockPrismaService.session.deleteMany).toHaveBeenCalledWith({
				where: { userId },
			});
		});
	});
});
