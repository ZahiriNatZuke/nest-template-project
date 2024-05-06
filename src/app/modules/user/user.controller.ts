import { Body, Delete, Get, HttpStatus, Param, Patch, Post, Query, Res } from '@nestjs/common';
import { ApiParam, ApiQuery } from '@nestjs/swagger';
import { UserPagination, UserService } from './user.service';

import { FindUserByIdPipe } from './pipes/find-user-by-id.pipe';
import { User } from '@prisma/client';
import { UserMapper } from './user.mapper';
import { isNil, omitBy } from 'lodash';
import { AuthRole } from '../auth/enums/auth-role';
import { Auth } from '../auth/decorators/auth.decorator';
import { SetController } from '../../core/decorators/set-controller.decorator';
import { ApiPaginationDecorator, PaginationDecorator } from '../../core/decorators/pagination.decorator';
import { Pagination } from '../../core/types/interfaces/pagination';
import { TrimQuerySearchPipe } from '../../core/pipes/trim-query-search/trim-query-search.pipe';
import { generateMeta } from '../../core/utils';
import { FastifyReply } from 'fastify';
import { CreateUserZodDto } from './dto/create-user.dto';
import { UpdateUserZodDto } from './dto/update-user.dto';

@SetController('user')
export class UserController {
  constructor(
    private userService: UserService,
    private userMapper: UserMapper,
  ) {
  }

  @Post()
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  async create(@Res() res: FastifyReply, @Body() payload: CreateUserZodDto) {
    const user = await this.userService.create(payload);
    return res.code(HttpStatus.CREATED).send({
      statusCode: 201,
      data: this.userMapper.omitDefault(user),
      message: 'User created',
    });
  }

  @Get()
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiQuery({ name: 'querySearch', required: false })
  @ApiPaginationDecorator()
  async findMany(
    @Res() res: FastifyReply,
    @PaginationDecorator() pagination: Pagination,
    @Query('querySearch', TrimQuerySearchPipe) querySearch: string,
  ) {
    const { take, page, url } = pagination;
    const paginationUser: UserPagination = {
      orderBy: { createdAt: 'asc' },
      take,
      skip: ( page - 1 ) * take,
      where: {
        OR: [
          {
            fullName: {
              contains: querySearch,
              mode: 'insensitive',
            },
          },
          {
            email: {
              contains: querySearch,
              mode: 'insensitive',
            },
          },
          {
            username: {
              contains: querySearch,
              mode: 'insensitive',
            },
          },
        ],
      },
    };
    const [ total, users ] = await this.userService.findMany(paginationUser);
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: users.map((user) => this.userMapper.omitDefault(user)),
      meta: generateMeta(total, take, page, url),
    });
  }

  @Get('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async findOne(
    @Res() res: FastifyReply,
    @Param('id', FindUserByIdPipe) user: User,
  ) {
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: this.userMapper.omitDefault(user),
    });
  }

  @Patch('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async update(
    @Res() res: FastifyReply,
    @Param('id', FindUserByIdPipe) { id }: User,
    @Body() payload: UpdateUserZodDto,
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

  @Delete('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async delete(
    @Res() res: FastifyReply,
    @Param('id', FindUserByIdPipe) { id }: User,
  ) {
    const userDeleted = await this.userService.delete({ id });
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: userDeleted,
      message: 'User deleted',
    });
  }

}
