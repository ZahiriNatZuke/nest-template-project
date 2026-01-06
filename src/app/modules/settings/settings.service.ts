import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateSettingsZodDto } from '@app/modules/settings/dto/create-settings.dto';
import { UpdateManySettingsZodDto } from '@app/modules/settings/dto/update-many-settings.dto';
import { UpdateSettingsZodDto } from '@app/modules/settings/dto/update-settings.dto';
import { Injectable } from '@nestjs/common';
import { Prisma, Settings } from '@prisma/client';
import { z } from 'zod';

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
		} catch (_e) {
			throw new ZodValidationException(
				new z.ZodError([
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

	async delete(where: Prisma.SettingsWhereUniqueInput): Promise<boolean> {
		try {
			await this.prisma.settings.delete({ where });
			return true;
		} catch (_e) {
			throw new ZodValidationException(
				new z.ZodError([
					{ code: 'custom', path: [], message: 'Delete setting failure' },
				])
			);
		}
	}
}
