import { AppController } from '@app/core/decorators/app-controller.decorator';
import {
	LenientThrottle,
	ModerateThrottle,
	StrictThrottle,
} from '@app/core/decorators/throttle.decorator';
import { CsrfService } from '@app/core/services/csrf/csrf.service';
import { TwoFactorService } from '@app/core/services/two-factor/two-factor.service';
import { AppRequest, AuthRequest } from '@app/core/types/app-request';
import { extractRequestInfo } from '@app/core/utils/request-info';
import { ConfirmEmailZodDto } from '@app/modules/auth/dto/confirm-email.dto';
import { ForgotPasswordZodDto } from '@app/modules/auth/dto/forgot-password.dto';
import { LoginZodDto } from '@app/modules/auth/dto/login.dto';
import { RecoveryAccountZodDto } from '@app/modules/auth/dto/recovery-account.dto';
import { RequestRecoveryAccountZodDto } from '@app/modules/auth/dto/request-recovery-account.dto';
import { ResetPasswordZodDto } from '@app/modules/auth/dto/reset-password.dto';
import { TokenZodDto } from '@app/modules/auth/dto/token.dto';
import { UpdatePasswordZodDto } from '@app/modules/auth/dto/update-password.dto';
import { CsrfGuard } from '@app/modules/auth/guards/csrf.guard';
import { JwtAuthGuard } from '@app/modules/auth/guards/jwt-auth.guard';
import { LocalAuthGuard } from '@app/modules/auth/guards/local-auth.guard';
import { UserMapper } from '@app/modules/user/user.mapper';
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
import { AuthService } from './auth.service';

@ApiTags('Authentication')
@AppController('auth')
export class AuthController {
	constructor(
		private authService: AuthService,
		private userService: UserService,
		private userMapper: UserMapper,
		private csrfService: CsrfService,
		private twoFactorService: TwoFactorService
	) {}

	@Get('csrf')
	@ApiOperation({
		summary: 'Get CSRF token',
		description: 'Generates and returns a CSRF token for form submissions',
	})
	@ApiResponse({
		status: 200,
		description: 'CSRF token generated successfully',
		schema: {
			example: {
				statusCode: 200,
				csrfToken: 'csrf-token-value',
			},
		},
	})
	async getCsrfToken(@Res() res: FastifyReply) {
		const csrfToken = this.csrfService.generateToken();

		res.header(
			'Set-Cookie',
			`XSRF-TOKEN=${csrfToken}; Path=/; HttpOnly=false; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict`
		);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			csrfToken,
		});
	}

	@Post('login')
	@StrictThrottle()
	@UseGuards(LocalAuthGuard, CsrfGuard)
	@ApiOperation({
		summary: 'User login',
		description:
			'Authenticates a user and returns access and refresh tokens via HttpOnly cookies. Rate limited to 5 requests per minute.',
	})
	@ApiResponse({
		status: 200,
		description: 'Login successful',
		schema: {
			example: {
				statusCode: 200,
				user: {
					id: 'user-id',
					email: 'user@example.com',
					fullName: 'John Doe',
				},
				message: 'Login Success',
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Invalid credentials or account not activated',
		schema: {
			example: {
				message: 'Login Failure',
			},
		},
	})
	@ApiResponse({
		status: 429,
		description: 'Too many requests - rate limit exceeded',
	})
	async login(
		@Res() res: FastifyReply,
		@Body() loginDTO: LoginZodDto,
		@Req() request: AppRequest
	) {
		const { device, rememberMe } = loginDTO;
		const { user: validatedUser } = request;

		if (!validatedUser.status || validatedUser.status === 'miss_activate') {
			throw new HttpException(
				{ message: 'Login Failure' },
				HttpStatus.UNAUTHORIZED
			);
		}

		// Extraer IP y User-Agent del request
		const { ipAddress, userAgent } = extractRequestInfo(request);

		const session = await this.authService.generateSession(
			validatedUser.user,
			device,
			ipAddress,
			userAgent
		);

		// ========== VALIDAR 2FA OBLIGATORIO ==========
		// Si el usuario tiene 2FA marcado como requerido, debe verificarlo antes de acceder
		if (
			validatedUser.user.twoFactorRequired &&
			validatedUser.user.twoFactorEnabled
		) {
			// Guardar sesión temporal en cookie con acceso limitado
			const tempAccessCookie = `tempAccessToken=${session.accessToken}; Path=/; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=600`;
			const refreshCookie = `refreshToken=${session.refreshToken}; Path=/api/v1/auth/refresh; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=600`;

			res.header('Set-Cookie', [tempAccessCookie, refreshCookie]);

			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				requiresTwoFactor: true,
				message:
					'2FA verification required. Please verify with your authenticator app or backup code.',
				sessionId: session.id,
			});
		}

		// Set HttpOnly cookies normales si 2FA no es requerido
		const accessCookie = `accessToken=${session.accessToken}; Path=/; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=900`;
		const refreshCookie = `refreshToken=${session.refreshToken}; Path=/api/v1/auth/refresh; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=${rememberMe ? 7 * 24 * 60 * 60 : ''}`;

		res.header('Set-Cookie', [accessCookie, refreshCookie]);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			user: validatedUser.user,
			message: 'Login Success',
			requiresTwoFactor: false,
		});
	}

	@Get('me')
	@LenientThrottle()
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Get current user',
		description: 'Returns the authenticated user profile',
	})
	@ApiResponse({
		status: 200,
		description: 'User profile retrieved successfully',
		schema: {
			example: {
				statusCode: 200,
				data: {
					id: 'user-id',
					email: 'user@example.com',
					username: 'johndoe',
					fullName: 'John Doe',
					confirmed: true,
					blocked: false,
				},
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Unauthorized - invalid or missing token',
	})
	@ApiResponse({
		status: 404,
		description: 'User not found',
	})
	async me(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id });
		if (!user) return res.code(HttpStatus.NOT_FOUND);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
		});
	}

	@Get('permissions/me')
	@LenientThrottle()
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Get current user permissions',
		description: 'Returns all permissions assigned to the authenticated user',
	})
	@ApiResponse({
		status: 200,
		description: 'Permissions retrieved successfully',
		schema: {
			example: {
				statusCode: 200,
				data: {
					permissions: [
						'users:read',
						'users:write',
						'roles:read',
						'api-keys:read',
					],
				},
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Unauthorized - invalid or missing token',
	})
	async getMyPermissions(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		// Retornar permisos desde JWT (cache) o DB fallback
		let permissions: string[];
		const userWithPerm = req.user as typeof req.user & { perm?: string[] };

		if (userWithPerm.perm && Array.isArray(userWithPerm.perm)) {
			permissions = userWithPerm.perm;
		} else {
			// Fallback: consultar DB
			const userRoles = await this.authService.getUserRolesWithPermissions(
				req.user.id
			);
			permissions = Array.from(
				new Set(
					userRoles.flatMap(ur =>
						ur.role.rolePermissions.map(rp => rp.permission.identifier)
					)
				)
			);
		}

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: { permissions },
		});
	}

	@Post('refresh')
	@UseGuards(CsrfGuard)
	@ApiOperation({
		summary: 'Refresh access token',
		description:
			'Refreshes the access token using a valid refresh token from HttpOnly cookie',
	})
	@ApiResponse({
		status: 200,
		description: 'Session refreshed successfully',
		schema: {
			example: {
				statusCode: 200,
				success: true,
				message: 'Refresh session successfully',
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Unauthorized - invalid or missing refresh token',
	})
	async refresh(@Res() res: FastifyReply, @Req() req: AppRequest) {
		const refreshToken = req.cookies?.refreshToken;

		if (!refreshToken) {
			return res.code(HttpStatus.UNAUTHORIZED).send({
				statusCode: 401,
				message: 'Refresh Failure',
			});
		}

		// Extraer IP y User-Agent del request para validación
		const { ipAddress, userAgent } = extractRequestInfo(req);

		const data = await this.authService.refreshSession(
			refreshToken,
			ipAddress,
			userAgent
		);

		if (data) {
			// Set new HttpOnly cookies
			const accessCookie = `accessToken=${data.session.accessToken}; Path=/; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=900`;
			const refreshCookie = `refreshToken=${data.session.refreshToken}; Path=/api/v1/auth/refresh; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`;

			res.header('Set-Cookie', [accessCookie, refreshCookie]);

			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				success: true,
				message: 'Refresh session successfully',
			});
		}

		return res.code(HttpStatus.UNAUTHORIZED).send({
			statusCode: 401,
			message: 'Refresh Failure',
		});
	}

	@Post('logout')
	@UseGuards(JwtAuthGuard, CsrfGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Logout user',
		description: 'Logs out the user and invalidates their session',
	})
	@ApiResponse({
		status: 200,
		description: 'Logout successful',
		schema: {
			example: {
				statusCode: 200,
				success: true,
				message: 'Logout Success',
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Unauthorized - invalid or missing token',
	})
	@ApiResponse({
		status: 403,
		description: 'Forbidden - logout failed',
	})
	async logout(@Res() res: FastifyReply, @Req() req: AppRequest) {
		const accessToken = req.cookies?.accessToken;
		const result = await this.authService.closeSession(accessToken);

		if (result) {
			// Clear cookies
			res.header('Set-Cookie', [
				'accessToken=; Path=/; HttpOnly; Max-Age=0',
				'refreshToken=; Path=/api/v1/auth/refresh; HttpOnly; Max-Age=0',
			]);

			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				success: true,
				message: 'Logout Success',
			});
		}

		return res.code(HttpStatus.FORBIDDEN).send({
			statusCode: 403,
			message: 'Logout Failure',
		});
	}

	@Post('update-password')
	@UseGuards(JwtAuthGuard)
	@ApiBearerAuth()
	@ApiOperation({
		summary: 'Update password',
		description: 'Updates the password for the authenticated user',
	})
	@ApiResponse({
		status: 200,
		description: 'Password changed successfully',
		schema: {
			example: {
				statusCode: 200,
				message: 'Password changed successfully',
			},
		},
	})
	@ApiResponse({
		status: 401,
		description: 'Unauthorized - invalid or missing token',
	})
	async updatePassword(
		@Res() res: FastifyReply,
		@Body() updatePasswordDto: UpdatePasswordZodDto,
		@Req() req: AuthRequest
	) {
		await this.authService.updatePassword(updatePasswordDto, req.user);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: 'Password changed successfully',
		});
	}

	@Post('request-recovery-account')
	@ModerateThrottle()
	@ApiOperation({
		summary: 'Request account recovery',
		description:
			'Initiates account recovery process. Rate limited to 3 requests per 5 minutes.',
	})
	@ApiResponse({
		status: 200,
		description: 'Recovery process started',
	})
	async requestRecoveryAccount(
		@Res() res: FastifyReply,
		@Body() requestRecoveryAccountDto: RequestRecoveryAccountZodDto
	) {
		await this.authService.requestRecoveryAccount(requestRecoveryAccountDto);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message:
				'Recovery account process started, now check the sms that you will receive in your phone',
		});
	}

	@Post('recovery-account')
	@ApiOperation({
		summary: 'Complete account recovery',
		description: 'Completes the account recovery process',
	})
	@ApiResponse({
		status: 200,
		description: 'Account recovered successfully',
	})
	async recoveryAccount(
		@Res() res: FastifyReply,
		@Body() recoveryAccountDto: RecoveryAccountZodDto
	) {
		await this.authService.recoverAccount(recoveryAccountDto);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: 'Recovery account successfully, now you can go to login page',
		});
	}

	@Post('verify-token')
	@ApiOperation({
		summary: 'Verify token',
		description: 'Verifies if a token is valid',
	})
	@ApiResponse({
		status: 200,
		description: 'Token is valid',
	})
	@ApiResponse({
		status: 400,
		description: 'Token is invalid',
	})
	async verifyToken(@Res() res: FastifyReply, @Body() body: TokenZodDto) {
		const { token } = body;
		const status = await this.authService.decodeVerificationToken(token);
		if (status)
			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				message: 'Verification process successfully',
			});

		return res.code(HttpStatus.BAD_REQUEST).send({
			statusCode: 400,
			message: 'Verification process failure',
		});
	}

	@Post('confirm-email')
	@ApiOperation({
		summary: 'Confirm email',
		description: 'Confirms user email address using a confirmation token',
	})
	@ApiResponse({
		status: 200,
		description: 'Email confirmed successfully',
	})
	async confirmEmail(
		@Res() res: FastifyReply,
		@Body() dto: ConfirmEmailZodDto
	) {
		await this.authService.confirmEmail(dto);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: 'Email confirmed successfully',
		});
	}

	@Post('forgot-password')
	@ModerateThrottle()
	@ApiOperation({
		summary: 'Forgot password',
		description:
			'Initiates password reset process. Rate limited to 3 requests per 5 minutes.',
	})
	@ApiResponse({
		status: 200,
		description: 'Password reset process started',
	})
	async forgotPassword(
		@Res() res: FastifyReply,
		@Body() dto: ForgotPasswordZodDto
	) {
		await this.authService.forgotPassword(dto);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message:
				'Password reset process started. TODO: send email with reset link/token',
		});
	}

	@Post('reset-password')
	@ModerateThrottle()
	@ApiOperation({
		summary: 'Reset password',
		description:
			'Resets user password using a reset token. Rate limited to 3 requests per 5 minutes.',
	})
	@ApiResponse({
		status: 200,
		description: 'Password reset successfully',
	})
	async resetPassword(
		@Res() res: FastifyReply,
		@Body() dto: ResetPasswordZodDto
	) {
		await this.authService.resetPassword(dto);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: 'Password reset successfully',
		});
	}

	// ========== 2FA Endpoints ==========

	@Get('2fa/setup')
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

	@Post('2fa/enable')
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

	@Post('2fa/verify')
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

	@Post('2fa/disable')
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

	@Post('2fa/regenerate-backup-codes')
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

	@Post('2fa/require')
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

	@Post('2fa/optional')
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
