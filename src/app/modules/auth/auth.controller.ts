import {
	Body,
	Get,
	Headers,
	HttpStatus,
	Post,
	Req,
	Res,
	UnauthorizedException,
	UseGuards,
} from '@nestjs/common';
import { Session, User } from '@prisma/client';
import { AuthService } from './auth.service';

import { AppController } from '@app/core/decorators';
import { AppRequest, AuthRequest } from '@app/core/types';
import { Auth } from '@app/modules/auth/decorators';
import {
	LoginZodDto,
	RecoveryAccountZodDto,
	RefreshZodDto,
	RequestRecoveryAccountZodDto,
	TokenZodDto,
} from '@app/modules/auth/dto';
import { UpdatePasswordZodDto } from '@app/modules/auth/dto/update-password.dto';
import { AuthRole } from '@app/modules/auth/enums';
import { LocalAuthGuard } from '@app/modules/auth/guards';
import { UserMapper } from '@app/modules/user/user.mapper';
import { UserService } from '@app/modules/user/user.service';
import { FastifyReply, FastifyRequest } from 'fastify';

@AppController('auth')
export class AuthController {
	constructor(
		private authService: AuthService,
		private userService: UserService,
		private userMapper: UserMapper
	) {}

	@Post('login')
	@UseGuards(LocalAuthGuard)
	async login(
		@Res() res: FastifyReply,
		@Body() loginDTO: LoginZodDto,
		@Req() { user: validatedUser }: AppRequest
	) {
		const { device } = loginDTO;
		if (!validatedUser.status || validatedUser.status === 'miss_activate') {
			throw new UnauthorizedException('Login Failure');
		}

		const session: Session = await this.authService.generateSession(
			validatedUser.user,
			device
		);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: {
				access: session.accessToken,
				refresh: session.refreshToken,
				user: validatedUser.user,
			},
			message: 'Login Success',
		});
	}

	@Get('me')
	@Auth(Object.values(AuthRole))
	async me(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		const user = await this.userService.findOne({ id: req.user.id });
		if (!user) return res.code(HttpStatus.NOT_FOUND);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
		});
	}

	@Post('refresh')
	async refresh(@Res() res: FastifyReply, @Body() refreshDto: RefreshZodDto) {
		const data = await this.authService.refreshSession(refreshDto.refresh);
		if (data) {
			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				data: {
					access: data.session.accessToken,
					refresh: data.session.refreshToken,
					user: this.userMapper.omitDefault(data.user),
				},
				message: 'Refresh session successfully',
			});
		}

		return res.code(HttpStatus.UNAUTHORIZED).send({
			statusCode: 401,
			message: 'Refresh Failure',
		});
	}

	@Get('logout')
	@Auth(Object.values(AuthRole))
	async logout(
		@Res() res: FastifyReply,
		@Headers('Authorization') headers: string
	) {
		const accessToken = headers.split(' ')[1];
		const result = await this.authService.closeSession(accessToken);
		if (result)
			return res.code(HttpStatus.OK).send({
				statusCode: 200,
				message: 'Logout Success',
			});

		return res.code(HttpStatus.FORBIDDEN).send({
			statusCode: 403,
			message: 'Logout Failure',
		});
	}

	@Post('update-password')
	@Auth(Object.values(AuthRole))
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
	async verifyToken(@Res() res: FastifyReply, @Body() { token }: TokenZodDto) {
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
