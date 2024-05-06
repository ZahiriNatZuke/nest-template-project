import { Body, Delete, Get, HttpStatus, Param, Patch, Post, Res } from '@nestjs/common';
import { Auth } from '../auth/decorators/auth.decorator';
import { AuthRole } from '../auth/enums/auth-role';
import { ApiParam } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { isNil, omitBy } from 'lodash';
import { RoleService } from './role.service';
import { CreateRoleZodDto } from './dto/create-role.dto';
import { UpdateRoleZodDto } from './dto/update-role.dto';
import { FindRoleByIdPipe } from './pipes/find-role-by-id/find-role-by-id.pipe';
import { SetController } from '../../core/decorators/set-controller.decorator';
import { FastifyReply } from 'fastify';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

@SetController('role')
export class RoleController {
  constructor(private roleService: RoleService) {
  }

  @Post()
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  async create(@Res() res: FastifyReply, @Body() payload: CreateRoleZodDto) {
    const role = await this.roleService.create(payload);
    return res.code(HttpStatus.CREATED).send({
      statusCode: 201,
      data: role,
      message: 'Role created',
    });
  }

  @Get()
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  async findMany(@Res() res: FastifyReply) {
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: await this.roleService.findMany(),
    });
  }

  @Get('/:id')
  @ApiParam({ name: 'id', type: 'string', required: true })
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  async findOne(
    @Res() res: FastifyReply,
    @Param('id', FindRoleByIdPipe) role: Role,
  ) {
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: role,
    });
  }

  @Patch('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async update(
    @Res() res: FastifyReply,
    @Param('id', FindRoleByIdPipe) { id }: Role,
    @Body() payload: UpdateRoleZodDto,
  ) {
    const role = await this.roleService.update({
      where: { id },
      data: omitBy(payload, isNil),
    });
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: role,
      message: 'Role updated',
    });
  }

  @Delete('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async delete(
    @Res() res: FastifyReply,
    @Param('id', FindRoleByIdPipe) role: Role,
  ) {
    if ( role.default ) {
      throw new ZodValidationException(
        z.ZodError.create([
          {
            code: 'custom',
            path: [],
            message: 'You cannot delete the default role',
          },
        ]),
      );
    }
    const roleDeleted = await this.roleService.delete({ id: role.id });
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: roleDeleted,
      message: 'Role deleted',
    });
  }
}
