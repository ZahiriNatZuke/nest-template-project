import { AppController } from '@app/core/decorators/app-controller.decorator';
import { LenientThrottle } from '@app/core/decorators/throttle.decorator';
import { AuthRequest } from '@app/core/types/app-request';
import { UpdatePasswordZodDto } from '@app/modules/auth/dto/update-password.dto';
import { JwtAuthGuard } from '@app/modules/auth/guards/jwt-auth.guard';
import { UserMapper } from '@app/modules/user/user.mapper';
import { UserService } from '@app/modules/user/user.service';
import {
	Body,
	Get,
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

@ApiTags('Authentication - Profile')
@AppController('auth')
export class ProfileController {
	constructor(
		private authService: AuthService,
		private userService: UserService,
		private userMapper: UserMapper
	) {}

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
}
