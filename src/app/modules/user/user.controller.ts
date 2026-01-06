import { AppController } from '@app/core/decorators/app-controller/app-controller.decorator';
import {
	ApiPaginationDecorator,
	PaginationDecorator,
} from '@app/core/decorators/paginator/pagination.decorator';
import { TrimQuerySearchPipe } from '@app/core/pipes/trim-query-search/trim-query-search.pipe';
import { Pagination } from '@app/core/types/interfaces/pagination';
import { generateMetadata } from '@app/core/utils/generate-metadata';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { AssignRoleZodDto } from '@app/modules/user/dto/assign-role.dto';
import { CreateUserZodDto } from '@app/modules/user/dto/create-user.dto';
import { UpdateUserZodDto } from '@app/modules/user/dto/update-user.dto';
import { FindUserByIdPipe } from '@app/modules/user/pipes/find-user-by-id.pipe';
import { UserMapper } from '@app/modules/user/user.mapper';
import {
	Body,
	Delete,
	Get,
	HttpStatus,
	Param,
	Patch,
	Post,
	Query,
	Res,
} from '@nestjs/common';
import { ApiParam, ApiQuery } from '@nestjs/swagger';
import { User } from '@prisma/client';
import { FastifyReply } from 'fastify';
import { isNil, omitBy } from 'lodash';
import { UserPagination, UserService } from './user.service';

@AppController('user')
export class UserController {
	constructor(
		private userService: UserService,
		private userMapper: UserMapper
	) {}

	@Post()
	@Authz('users:write')
	async create(@Res() res: FastifyReply, @Body() payload: CreateUserZodDto) {
		const user = await this.userService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: this.userMapper.omitDefault(user),
			message: 'User created',
		});
	}

	@Get()
	@Authz('users:read')
	@ApiQuery({ name: 'querySearch', required: false })
	@ApiPaginationDecorator()
	async findMany(
		@Res() res: FastifyReply,
		@PaginationDecorator() pagination: Pagination,
		@Query('querySearch', TrimQuerySearchPipe) querySearch: string
	) {
		const { take, page, url } = pagination;
		const paginationUser: UserPagination = {
			orderBy: { createdAt: 'asc' },
			take,
			skip: (page - 1) * take,
			where: {
				OR: [
					{
						fullName: {
							contains: querySearch,
						},
					},
					{
						email: {
							contains: querySearch,
						},
					},
					{
						username: {
							contains: querySearch,
						},
					},
				],
			},
		};
		const [total, users] = await this.userService.findMany(paginationUser);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: users.map(user => this.userMapper.omitDefault(user)),
			meta: generateMetadata({ total, take, page, url }),
		});
	}

	@Get(':id')
	@Authz('users:read')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async findOne(
		@Res() res: FastifyReply,
		@Param('id', FindUserByIdPipe) user: User
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
		});
	}

	@Patch(':id')
	@Authz('users:write')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Param('id', FindUserByIdPipe) { id }: User,
		@Body() payload: UpdateUserZodDto
	) {
		const user = await this.userService.update({
			where: { id },
			data: omitBy(payload, isNil),
		});
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
			message: 'User updated',
		});
	}

	@Delete(':id')
	@Authz('users:delete')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(
		@Res() res: FastifyReply,
		@Param('id', FindUserByIdPipe) { id }: User
	) {
		const userDeleted = await this.userService.delete({ id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: userDeleted,
			message: 'User deleted',
		});
	}

	@Post(':id/roles')
	@Authz('users:write')
	@ApiParam({ name: 'id', type: String })
	async assignRole(
		@Res() res: FastifyReply,
		@Param('id') userId: string,
		@Body() payload: AssignRoleZodDto
	) {
		const user = await this.userService.assignRole(userId, payload.roleId);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
			message: 'Role assigned to user',
		});
	}

	@Delete(':id/roles/:roleId')
	@Authz('users:write')
	@ApiParam({ name: 'id', type: String })
	@ApiParam({ name: 'roleId', type: String })
	async removeRole(
		@Res() res: FastifyReply,
		@Param('id') userId: string,
		@Param('roleId') roleId: string
	) {
		const user = await this.userService.removeRole(userId, roleId);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: this.userMapper.omitDefault(user),
			message: 'Role removed from user',
		});
	}
}
