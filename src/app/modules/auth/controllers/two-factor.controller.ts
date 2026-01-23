import { AppController } from '@app/core/decorators/app-controller.decorator';
import { StrictThrottle } from '@app/core/decorators/throttle.decorator';
import { TwoFactorService } from '@app/core/services/two-factor/two-factor.service';
import { AppRequest, AuthRequest } from '@app/core/types/app-request';
import { extractRequestInfo } from '@app/core/utils/request-info';
import { JwtAuthGuard } from '@app/modules/auth/guards/jwt-auth.guard';
import { UserService } from '@app/modules/user/user.service';
import {
	Body,
	Get,
	HttpException,
	HttpStatus,
	Post,
	Req,
	Res,
	UseGuards,
} from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiOperation,
	ApiResponse,
	ApiTags,
} from '@nestjs/swagger';
import { FastifyReply } from 'fastify';

@ApiTags('Authentication - Two-Factor')
@AppController('auth/2fa')
export class TwoFactorController {
	constructor(
		private userService: UserService,
		private twoFactorService: TwoFactorService
	) {}

	@Get('setup')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Setup 2FA',
		description: 'Generate QR code and secret for 2FA setup',
	})
	@ApiResponse({
		status: 200,
		description: '2FA setup initiated',
		schema: {
			example: {
				statusCode: 200,
				data: {
					qrCode: 'data:image/png;base64,...',
					secret: 'JBSWY3DPEHPK3PXP',
					backupCodes: ['ABC123DE', 'FGH456IJ'],
				},
			},
		},
	})
	async setup2FA(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (user.twoFactorEnabled) {
			throw new HttpException(
				{ message: '2FA is already enabled' },
				HttpStatus.BAD_REQUEST
			);
		}

		const secret = this.twoFactorService.generateSecret();
		const qrCode = await this.twoFactorService.generateQRCode(
			user.email,
			secret
		);
		const backupCodes = this.twoFactorService.generateBackupCodes();

		// Store secret temporarily in session or return it for verification
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: {
				qrCode,
				secret, // User needs this to verify before enabling
				backupCodes, // Show once, user must save them
			},
			message:
				'Scan QR code with your authenticator app and verify with a token to enable 2FA',
		});
	}

	@Post('enable')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@StrictThrottle()
	@ApiOperation({
		summary: 'Enable 2FA',
		description: 'Verify TOTP token and enable 2FA for the user',
	})
	@ApiResponse({
		status: 200,
		description: '2FA enabled successfully',
	})
	async enable2FA(
		@Res() res: FastifyReply,
		@Req() req: AuthRequest,
		@Body() body: { token: string; secret: string; backupCodes: string[] }
	) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (user.twoFactorEnabled) {
			throw new HttpException(
				{ message: '2FA is already enabled' },
				HttpStatus.BAD_REQUEST
			);
		}

		// Verify the token with the provided secret
		const isValid = await this.twoFactorService.verifyToken(
			body.token,
			body.secret
		);

		if (!isValid) {
			throw new HttpException(
				{ message: 'Invalid TOTP token' },
				HttpStatus.BAD_REQUEST
			);
		}

		// Enable 2FA
		await this.twoFactorService.enable2FA({
			userId: user.id,
			secret: body.secret,
			backupCodes: body.backupCodes,
		});

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: '2FA enabled successfully. Save your backup codes securely.',
		});
	}

	@Post('verify')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@StrictThrottle()
	@ApiOperation({
		summary: 'Verify 2FA',
		description: 'Verify 2FA token during login or sensitive operations',
	})
	@ApiResponse({
		status: 200,
		description: '2FA verification successful',
	})
	async verify2FA(
		@Res() res: FastifyReply,
		@Req() req: AuthRequest & AppRequest,
		@Body() body: { token: string }
	) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (!user.twoFactorEnabled || !user.twoFactorSecret) {
			throw new HttpException(
				{ message: '2FA is not enabled' },
				HttpStatus.BAD_REQUEST
			);
		}

		const { ipAddress, userAgent } = extractRequestInfo(req);

		// Check if too many failed attempts
		const { exceeded } = await this.twoFactorService.checkFailedAttempts(
			user.id
		);

		if (exceeded) {
			throw new HttpException(
				{
					message: 'Too many failed 2FA attempts. Account temporarily locked.',
				},
				HttpStatus.TOO_MANY_REQUESTS
			);
		}

		// Try TOTP verification first
		let isValid = await this.twoFactorService.verifyToken(
			body.token,
			user.twoFactorSecret
		);

		// If TOTP fails, try backup code
		if (!isValid) {
			isValid = await this.twoFactorService.verifyBackupCode(
				user.id,
				body.token
			);
		}

		// Record attempt
		await this.twoFactorService.recordAttempt({
			userId: user.id,
			success: isValid,
			ipAddress,
			userAgent,
		});

		if (!isValid) {
			throw new HttpException(
				{ message: 'Invalid 2FA token or backup code' },
				HttpStatus.UNAUTHORIZED
			);
		}

		// ========== 2FA VERIFICATION SUCCESS ==========
		// Si 2FA es requerido y se verificó correctamente, completar login
		if (user.twoFactorRequired) {
			// El accessToken ya está en tempAccessToken, simplemente cambiarlo a accessToken
			const accessCookie = `accessToken=${req.cookies?.tempAccessToken || req.cookies?.accessToken}; Path=/; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=900`;

			res.header('Set-Cookie', accessCookie);

			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				message: '2FA verification successful. Login completed.',
				loginCompleted: true,
			});
		}

		// Si 2FA no es requerido, solo confirmar verificación
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: '2FA verification successful',
		});
	}

	@Post('disable')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Disable 2FA',
		description: 'Disable 2FA for the user',
	})
	@ApiResponse({
		status: 200,
		description: '2FA disabled successfully',
	})
	async disable2FA(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (!user.twoFactorEnabled) {
			throw new HttpException(
				{ message: '2FA is not enabled' },
				HttpStatus.BAD_REQUEST
			);
		}

		await this.twoFactorService.disable2FA(user.id);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: '2FA disabled successfully',
		});
	}

	@Post('regenerate-backup-codes')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Regenerate backup codes',
		description: 'Generate new backup codes for 2FA',
	})
	@ApiResponse({
		status: 200,
		description: 'Backup codes regenerated',
	})
	async regenerateBackupCodes(
		@Res() res: FastifyReply,
		@Req() req: AuthRequest
	) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (!user.twoFactorEnabled) {
			throw new HttpException(
				{ message: '2FA is not enabled' },
				HttpStatus.BAD_REQUEST
			);
		}

		const backupCodes = await this.twoFactorService.regenerateBackupCodes(
			user.id
		);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: { backupCodes },
			message: 'Backup codes regenerated. Save them securely.',
		});
	}

	@Post('require')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Mark 2FA as required',
		description:
			'Mark 2FA as mandatory for the user. User must have 2FA enabled first.',
	})
	@ApiResponse({
		status: 200,
		description: '2FA marked as required',
	})
	async require2FA(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		if (!user.twoFactorEnabled) {
			throw new HttpException(
				{
					message: 'Cannot require 2FA if not enabled. Enable it first.',
				},
				HttpStatus.BAD_REQUEST
			);
		}

		await this.twoFactorService.require2FA(user.id);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message:
				'2FA is now required for your account. You must verify it on every login.',
		});
	}

	@Post('optional')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Mark 2FA as optional',
		description: 'Mark 2FA as optional for the user.',
	})
	@ApiResponse({
		status: 200,
		description: '2FA marked as optional',
	})
	async make2FAOptional(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id }, true);

		if (!user) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}

		await this.twoFactorService.make2FAOptional(user.id);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: '2FA is now optional for your account.',
		});
	}
}
