import { SafeUser, ValidatedUser } from '@app/core/types';
import { envs } from '@app/env';
import {
	RecoveryAccountZodDto,
	RequestRecoveryAccountZodDto,
	UpdatePasswordZodDto,
} from '@app/modules/auth/dto';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { pick } from 'lodash';
import { PrismaService } from 'nestjs-prisma';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';
import { v4 } from 'uuid';
import { UserMapper } from '../user/user.mapper';
import { UserService } from '../user/user.service';
import { JWTPayload } from './interface/jwt.payload';

@Injectable()
export class AuthService {
	constructor(
		private prisma: PrismaService,
		private jwtService: JwtService,
		private userMapper: UserMapper,
		private userService: UserService
	) {}

	async validateUser(identifier: string, pass: string): Promise<ValidatedUser> {
		try {
			const user: User = await this.prisma.user.findFirstOrThrow({
				where: {
					OR: [{ email: identifier }, { username: identifier }],
				},
				take: 1,
				include: { role: true },
			});

			if (user.confirmed && !user.blocked) {
				return {
					status: await bcrypt.compare(pass, user.password ?? ''),
					user: this.userMapper.omitDefault(user),
				};
			}
			if (!user.blocked) {
				return {
					status: 'miss_activate',
					user: this.userMapper.omitDefault(user),
				};
			}

			return {
				user: null,
				status: false,
			};
		} catch (e) {
			throw new UnauthorizedException('Login Failure');
		}
	}

	async generateSession(user: SafeUser, device: string) {
		const data: JWTPayload = {
			userId: user.id,
			device,
			email: user.email,
			fullName: user.fullName,
		};

		try {
			const { id } = await this.prisma.session.findUniqueOrThrow({
				where: { device },
			});

			return this.prisma.session.update({
				where: { id },
				data: {
					accessToken: this.jwtService.sign(data),
					refreshToken: this.jwtService.sign(data, {
						secret: envs.JWT_REFRESH_TOKEN_SECRET,
						expiresIn: envs.EXPIRESIN_REFRESH,
					}),
				},
			});
		} catch (_) {
			return this.prisma.session.create({
				data: {
					userId: user.id,
					device,
					accessToken: this.jwtService.sign(data),
					refreshToken: this.jwtService.sign(data, {
						secret: envs.JWT_REFRESH_TOKEN_SECRET,
						expiresIn: envs.EXPIRESIN_REFRESH,
					}),
				},
			});
		}
	}

	async refreshSession(refreshToken: string) {
		try {
			const currentSession = await this.prisma.session.findUniqueOrThrow({
				where: { refreshToken },
			});
			const user = await this.prisma.user.findUniqueOrThrow({
				where: { id: currentSession.userId },
				include: { role: true },
			});

			const data: JWTPayload = {
				userId: currentSession.userId,
				device: currentSession.device,
				email: user.email,
				fullName: user.fullName,
			};

			const session = await this.prisma.session.update({
				where: { refreshToken },
				data: {
					accessToken: this.jwtService.sign(data),
					refreshToken: this.jwtService.sign(data, {
						secret: envs.JWT_REFRESH_TOKEN_SECRET,
					}),
				},
			});

			return { session, user };
		} catch (_) {
			return null;
		}
	}

	async closeSession(accessToken: string) {
		try {
			await this.prisma.session.findUniqueOrThrow({
				where: { accessToken },
			});

			await this.prisma.session.delete({
				where: { accessToken },
			});

			return true;
		} catch (_) {
			return false;
		}
	}

	async validateApiKey(apikey: string) {
		try {
			await this.prisma.apiKey.findUniqueOrThrow({
				where: { key: apikey },
			});
			return true;
		} catch (_) {
			return false;
		}
	}

	async updatePassword(dto: UpdatePasswordZodDto, user: User) {
		const userDb = await this.prisma.user.findUniqueOrThrow({
			where: { id: user.id },
		});

		if (!(await bcrypt.compare(dto.current_password, user.password)))
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Current password miss match',
					},
				])
			);

		if (dto.new_password !== dto.confirm_new_password) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Passwords not match',
					},
				])
			);
		}

		const newPassword = await bcrypt.hash(
			dto.new_password,
			bcrypt.genSaltSync(16)
		);
		return this.prisma.user.update({
			where: { id: userDb.id },
			data: { password: newPassword },
		});
	}

	async recoverAccount(dto: RecoveryAccountZodDto) {
		if (dto.newPassword !== dto.confirmNewPassword) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Passwords not match',
					},
				])
			);
		}

		try {
			const userDb = await this.prisma.user.findUniqueOrThrow({
				where: { email: dto.email },
			});

			const newPassword = await bcrypt.hash(
				dto.newPassword,
				bcrypt.genSaltSync(16)
			);
			return this.prisma.user.update({
				where: { id: userDb.id },
				data: { password: newPassword },
			});
		} catch (_) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Recovery account process failure',
					},
				])
			);
		}
	}

	async requestRecoveryAccount(dto: RequestRecoveryAccountZodDto) {
		try {
			const user = await this.userService.findOne({ email: dto.email }, true);

			const payload = pick(user, ['name', 'lastname', 'email', 'id']);
			const token = this.jwtService.sign(
				{ ...payload, xhr: v4() },
				{
					secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
					expiresIn: envs.JWT_VERIFICATION_TOKEN_EXPIRATION_TIME,
				}
			);
			const url = `${envs.RECOVERY_ACCOUNT_URL}?token=${token}&email=${dto.email}`;

			new Logger(AuthService.name).debug(`>> [recovery-url]: ${url}`);
		} catch (e) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Request for recovery account failure',
					},
				])
			);
		}
	}

	async decodeVerificationToken(token: string): Promise<boolean> {
		try {
			const payload = await this.jwtService.verify(token, {
				secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
			});

			return typeof payload === 'object' && 'xhr' in payload;
		} catch (error) {
			if (error?.name === 'TokenExpiredError') {
				throw new ZodValidationException(
					z.ZodError.create([
						{
							code: 'custom',
							path: [],
							message: 'Recovered process expired, you must restart process',
						},
					])
				);
			}
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Verification of recovery process failure',
					},
				])
			);
		}
	}
}
