import { Injectable } from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import { CreateRoleZodDto } from './dto/create-role.dto';
import { PrismaService } from '../../core/modules/prisma/prisma.service';
import { UpdateRoleZodDto } from './dto/update-role.dto';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

@Injectable()
export class RoleService {
  constructor(private prisma: PrismaService) {
  }

  async findMany() {
    return this.prisma.role.findMany();
  }

  async findOne(
    roleWhereUniqueInput: Prisma.RoleWhereUniqueInput,
    canThrow = false,
  ): Promise<Role | null> {
    if ( canThrow )
      return this.prisma.role.findUniqueOrThrow({
        where: roleWhereUniqueInput,
        include: { users: true },
      });
    else
      return this.prisma.role.findUnique({
        where: roleWhereUniqueInput,
        include: { users: true },
      });
  }

  async create(data: CreateRoleZodDto): Promise<Role> {
    try {
      return this.prisma.role.create({ data });
    } catch ( e ) {
      throw new ZodValidationException(
        z.ZodError.create([
          {
            code: 'custom',
            path: [],
            message: 'Create role failure',
          },
        ]),
      );
    }
  }

  async update(params: {
    where: Prisma.RoleWhereUniqueInput;
    data: UpdateRoleZodDto;
  }): Promise<Role> {
    const { where, data } = params;
    await this.prisma.role.update({
      where,
      data,
    });

    return this.prisma.role.findUniqueOrThrow({ where, include: { users: true } });
  }

  async delete(where: Prisma.RoleWhereUniqueInput): Promise<Role> {
    return this.prisma.role.delete({ where });
  }
}
