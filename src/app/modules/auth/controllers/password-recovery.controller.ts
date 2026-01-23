import { AppController } from '@app/core/decorators/app-controller.decorator';
import { ModerateThrottle } from '@app/core/decorators/throttle.decorator';
import { ConfirmEmailZodDto } from '@app/modules/auth/dto/confirm-email.dto';
import { ForgotPasswordZodDto } from '@app/modules/auth/dto/forgot-password.dto';
import { RecoveryAccountZodDto } from '@app/modules/auth/dto/recovery-account.dto';
import { RequestRecoveryAccountZodDto } from '@app/modules/auth/dto/request-recovery-account.dto';
import { ResetPasswordZodDto } from '@app/modules/auth/dto/reset-password.dto';
import { TokenZodDto } from '@app/modules/auth/dto/token.dto';
import { Body, HttpStatus, Post, Res } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { FastifyReply } from 'fastify';
import { AuthService } from '../auth.service';

@ApiTags('Authentication - Password Recovery')
@AppController('auth')
export class PasswordRecoveryController {
	constructor(private authService: AuthService) {}

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
