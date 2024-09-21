import {
	CreateSettingsZodDto,
	UpdateManySettingsZodDto,
	UpdateSettingsZodDto,
} from '@app/modules/settings/dto';
import { Injectable } from '@nestjs/common';
import { Prisma, Settings } from '@prisma/client';
import { PrismaService } from 'nestjs-prisma';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

@Injectable()
export class SettingsService {
	constructor(private prisma: PrismaService) {}

	async findMany() {
		return this.prisma.settings.findMany({
			where: {
				key: {
					notIn: [],
				},
			},
		});
	}

	async findOne(
		settingsWhereUniqueInput: Prisma.SettingsWhereUniqueInput,
		canThrow = false
	): Promise<Settings | null> {
		if (canThrow)
			return this.prisma.settings.findUniqueOrThrow({
				where: settingsWhereUniqueInput,
			});

		return this.prisma.settings.findUnique({
			where: settingsWhereUniqueInput,
		});
	}

	async create(data: CreateSettingsZodDto): Promise<Settings> {
		try {
			return this.prisma.settings.create({
				data: {
					value: data.value,
					key: data.key,
				},
			});
		} catch (e) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'Create setting failure',
					},
				])
			);
		}
	}

	async update(params: {
		where: Prisma.SettingsWhereUniqueInput;
		data: UpdateSettingsZodDto;
	}): Promise<Settings> {
		const { where, data } = params;
		await this.prisma.settings.update({
			where,
			data,
		});

		return this.prisma.settings.findUniqueOrThrow({ where });
	}

	async updateMany({ data }: UpdateManySettingsZodDto): Promise<Settings[]> {
		for (const elm of data) {
			const { key, value } = elm;
			await this.update({ where: { key }, data: { value } });
		}

		return this.prisma.settings.findMany({
			where: {
				OR: data.map(e => ({ key: e.key })),
			},
		});
	}
}
