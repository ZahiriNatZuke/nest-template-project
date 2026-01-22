import { AppController } from '@app/core/decorators/app-controller.decorator';
import {
	LenientThrottle,
	ModerateThrottle,
	StrictThrottle,
} from '@app/core/decorators/throttle.decorator';
import { CsrfService } from '@app/core/services/csrf/csrf.service';
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
		private csrfService: CsrfService
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

		// Set HttpOnly cookies
		const accessCookie = `accessToken=${session.accessToken}; Path=/; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=900`;
		const refreshCookie = `refreshToken=${session.refreshToken}; Path=/api/v1/auth/refresh; HttpOnly; Secure=${process.env.NODE_ENV === 'production'}; SameSite=Strict; Max-Age=${rememberMe ? 7 * 24 * 60 * 60 : ''}`;

		res.header('Set-Cookie', [accessCookie, refreshCookie]);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			user: validatedUser.user,
			message: 'Login Success',
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
}
