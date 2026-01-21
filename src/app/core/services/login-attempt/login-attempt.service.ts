import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';

/**
 * Configuración de protección contra brute force
 */
export const BRUTE_FORCE_CONFIG = {
	// Máximo de intentos fallidos permitidos
	MAX_ATTEMPTS: 5,
	// Período de tiempo en minutos
	WINDOW_MINUTES: 15,
	// Duración del bloqueo en minutos
	LOCKOUT_MINUTES: 30,
};

export interface LoginAttemptInfo {
	identifier: string;
	ipAddress: string;
	userAgent?: string;
}

@Injectable()
export class LoginAttemptService {
	private readonly logger = new Logger(LoginAttemptService.name);

	constructor(private prisma: PrismaService) {}

	/**
	 * Registra un intento de login fallido
	 */
	async recordFailedAttempt(info: LoginAttemptInfo): Promise<void> {
		try {
			await this.prisma.loginAttempt.create({
				data: {
					identifier: info.identifier,
					ipAddress: info.ipAddress,
					userAgent: info.userAgent,
					success: false,
				},
			});

			this.logger.warn(
				`Failed login attempt for identifier: ${info.identifier} from IP: ${info.ipAddress}`
			);
		} catch (error) {
			this.logger.error('Error recording failed login attempt', error);
		}
	}

	/**
	 * Registra un intento de login exitoso
	 */
	async recordSuccessfulAttempt(info: LoginAttemptInfo): Promise<void> {
		try {
			await this.prisma.loginAttempt.create({
				data: {
					identifier: info.identifier,
					ipAddress: info.ipAddress,
					userAgent: info.userAgent,
					success: true,
				},
			});

			this.logger.debug(
				`Successful login for identifier: ${info.identifier} from IP: ${info.ipAddress}`
			);
		} catch (error) {
			this.logger.error('Error recording successful login attempt', error);
		}
	}

	/**
	 * Comprueba si el identifier está bloqueado por brute force
	 * Retorna true si está bloqueado, false si puede intentar
	 */
	async isBlocked(identifier: string): Promise<boolean> {
		const now = new Date();
		const windowStart = new Date(
			now.getTime() - BRUTE_FORCE_CONFIG.WINDOW_MINUTES * 60 * 1000
		);

		try {
			// Contar intentos fallidos en la ventana de tiempo
			const failedAttempts = await this.prisma.loginAttempt.count({
				where: {
					identifier,
					success: false,
					createdAt: {
						gte: windowStart,
					},
				},
			});

			const isBlocked = failedAttempts >= BRUTE_FORCE_CONFIG.MAX_ATTEMPTS;

			if (isBlocked) {
				this.logger.warn(
					`Identifier ${identifier} is blocked due to too many failed attempts (${failedAttempts})`
				);
			}

			return isBlocked;
		} catch (error) {
			this.logger.error('Error checking if identifier is blocked', error);
			// En caso de error, permitir el intento (fail open)
			return false;
		}
	}

	/**
	 * Comprueba si una IP está bloqueada por brute force
	 */
	async isIPBlocked(ipAddress: string): Promise<boolean> {
		const now = new Date();
		const windowStart = new Date(
			now.getTime() - BRUTE_FORCE_CONFIG.WINDOW_MINUTES * 60 * 1000
		);

		try {
			// Contar intentos fallidos desde esta IP
			const failedAttempts = await this.prisma.loginAttempt.count({
				where: {
					ipAddress,
					success: false,
					createdAt: {
						gte: windowStart,
					},
				},
			});

			const isBlocked = failedAttempts >= BRUTE_FORCE_CONFIG.MAX_ATTEMPTS;

			if (isBlocked) {
				this.logger.warn(
					`IP ${ipAddress} is blocked due to too many failed login attempts (${failedAttempts})`
				);
			}

			return isBlocked;
		} catch (error) {
			this.logger.error('Error checking if IP is blocked', error);
			return false;
		}
	}

	/**
	 * Obtiene el número de intentos fallidos de un identifier
	 */
	async getFailedAttemptCount(identifier: string): Promise<number> {
		const now = new Date();
		const windowStart = new Date(
			now.getTime() - BRUTE_FORCE_CONFIG.WINDOW_MINUTES * 60 * 1000
		);

		try {
			return await this.prisma.loginAttempt.count({
				where: {
					identifier,
					success: false,
					createdAt: {
						gte: windowStart,
					},
				},
			});
		} catch (error) {
			this.logger.error('Error getting failed attempt count', error);
			return 0;
		}
	}

	/**
	 * Limpia intentos de login antiguos
	 * Debería ejecutarse como cron job
	 */
	async cleanupOldAttempts(): Promise<number> {
		const cutoffDate = new Date(
			Date.now() - BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES * 60 * 1000
		);

		try {
			const result = await this.prisma.loginAttempt.deleteMany({
				where: {
					createdAt: {
						lt: cutoffDate,
					},
				},
			});

			this.logger.log(`Cleaned up ${result.count} old login attempts`);
			return result.count;
		} catch (error) {
			this.logger.error('Error cleaning up old login attempts', error);
			return 0;
		}
	}

	/**
	 * Desbloquea un identifier manualmente
	 */
	async unlockIdentifier(identifier: string): Promise<void> {
		try {
			await this.prisma.loginAttempt.deleteMany({
				where: {
					identifier,
					success: false,
				},
			});

			this.logger.log(`Manually unlocked identifier: ${identifier}`);
		} catch (error) {
			this.logger.error('Error unlocking identifier', error);
		}
	}

	/**
	 * Validar que el usuario puede intentar login
	 * Lanza excepción si está bloqueado
	 */
	async validateLoginAttempt(
		identifier: string,
		ipAddress: string
	): Promise<void> {
		const isIdentifierBlocked = await this.isBlocked(identifier);
		const isIPBlocked = await this.isIPBlocked(ipAddress);

		if (isIdentifierBlocked) {
			throw new HttpException(
				{
					statusCode: HttpStatus.TOO_MANY_REQUESTS,
					message: `Too many failed login attempts. Try again in ${BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES} minutes.`,
				},
				HttpStatus.TOO_MANY_REQUESTS
			);
		}

		if (isIPBlocked) {
			throw new HttpException(
				{
					statusCode: HttpStatus.TOO_MANY_REQUESTS,
					message: `Too many login attempts from your IP. Try again in ${BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES} minutes.`,
				},
				HttpStatus.TOO_MANY_REQUESTS
			);
		}
	}
}
