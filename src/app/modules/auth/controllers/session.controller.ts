import { AppController } from '@app/core/decorators/app-controller.decorator';
import { StrictThrottle } from '@app/core/decorators/throttle.decorator';
import { CsrfService } from '@app/core/services/csrf/csrf.service';
import { AppRequest } from '@app/core/types/app-request';
import { extractRequestInfo } from '@app/core/utils/request-info';
import { LoginZodDto } from '@app/modules/auth/dto/login.dto';
import { CsrfGuard } from '@app/modules/auth/guards/csrf.guard';
import { JwtAuthGuard } from '@app/modules/auth/guards/jwt-auth.guard';
import { LocalAuthGuard } from '@app/modules/auth/guards/local-auth.guard';
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
import { AuthService } from '../auth.service';

@ApiTags('Authentication - Session')
@AppController('auth')
export class SessionController {
	constructor(
		private authService: AuthService,
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
}
