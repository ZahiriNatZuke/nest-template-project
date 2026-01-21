import { AppController } from '@app/core/decorators/app-controller/app-controller.decorator';
import { CsrfService } from '@app/core/services/csrf/csrf.service';
import { AppRequest, AuthRequest } from '@app/core/types/app-request';
import { extractRequestInfo } from '@app/core/utils/request-info';
import { LoginZodDto } from '@app/modules/auth/dto/login.dto';
import { RecoveryAccountZodDto } from '@app/modules/auth/dto/recovery-account.dto';
import { RequestRecoveryAccountZodDto } from '@app/modules/auth/dto/request-recovery-account.dto';
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
import { FastifyReply } from 'fastify';
import { AuthService } from './auth.service';

@AppController('auth')
export class AuthController {
	constructor(
		private authService: AuthService,
		private userService: UserService,
		private userMapper: UserMapper,
		private csrfService: CsrfService
	) {}

	@Get('csrf')
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
	@UseGuards(LocalAuthGuard, CsrfGuard)
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
	@UseGuards(JwtAuthGuard)
	async me(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id });
		if (!user) return res.code(HttpStatus.NOT_FOUND);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
		});
	}

	@Get('permissions/me')
	@UseGuards(JwtAuthGuard)
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
}
