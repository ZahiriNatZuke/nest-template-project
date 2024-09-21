import { AuthRole } from '@app/modules/auth/enums';
import { CreateUserZodDto, UpdateUserZodDto } from '@app/modules/user/dto';
import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'nestjs-prisma';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export interface UserPagination {
	skip?: number;
	take?: number;
	where?: Prisma.UserWhereInput;
	orderBy?: Prisma.UserOrderByWithRelationInput;
}

@Injectable()
export class UserService {
	constructor(private prisma: PrismaService) {}

	async findOne(
		userWhereUniqueInput: Prisma.UserWhereUniqueInput,
		canThrow = false
	): Promise<User | null> {
		if (canThrow)
			return this.prisma.user.findUniqueOrThrow({
				where: userWhereUniqueInput,
				include: { role: true },
			});

		return this.prisma.user.findUnique({
			where: userWhereUniqueInput,
			include: { role: true },
		});
	}

	async findMany(params: UserPagination): Promise<[number, User[]]> {
		const { skip, take, where, orderBy } = params;
		return this.prisma.$transaction([
			this.prisma.user.count({
				where,
				orderBy,
			}),
			this.prisma.user.findMany({
				skip,
				take,
				where,
				orderBy,
				include: { role: true },
			}),
		]);
	}

	async create(data: CreateUserZodDto): Promise<User> {
		return this.createUser(data);
	}

	async update(params: {
		where: Prisma.UserWhereUniqueInput;
		data: UpdateUserZodDto;
	}): Promise<User> {
		const { where, data } = params;
		await this.prisma.user.update({
			where,
			data,
		});

		return this.prisma.user.findUniqueOrThrow({
			where,
			include: { role: true },
		});
	}

	async delete(where: Prisma.UserWhereUniqueInput): Promise<User> {
		return this.prisma.user.delete({
			where,
		});
	}

	private async createUser(payload: CreateUserZodDto) {
		const { password, ...input } = payload;
		const pwd = await bcrypt.hash(password, bcrypt.genSaltSync(16));
		const { id } = await this.prisma.role.findUniqueOrThrow({
			where: { identifier: AuthRole.USER_ROLE },
		});

		if (id) {
			try {
				const user = await this.prisma.user.create({
					data: {
						...input,
						password: pwd,
						roleId: id,
						confirmed: true,
					},
				});

				return this.prisma.user.findUniqueOrThrow({
					where: { id: user.id },
					include: { role: true },
				});
			} catch (e) {
				throw new ZodValidationException(
					z.ZodError.create([
						{
							code: 'custom',
							path: [],
							message: 'Create user failure',
						},
					])
				);
			}
		} else {
			throw new NotFoundException('Default Role not found');
		}
	}
}
