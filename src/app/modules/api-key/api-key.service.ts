import { Injectable } from '@nestjs/common';
import { ApiKey, Prisma } from '@prisma/client';
import { CreateApiKeyZodDto } from './dto/create-api-key.dto';
import { UpdateApiKeyZodDto } from './dto/update-api-key.dto';
import { PrismaService } from '../../core/modules/prisma/prisma.service';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

@Injectable()
export class ApiKeyService {
  constructor(private prisma: PrismaService) {
  }

  async findMany() {
    return this.prisma.apiKey.findMany({
      select: {
        id: true,
        application: true,
        default: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  async findOne(
    apiKeyWhereUniqueInput: Prisma.ApiKeyWhereUniqueInput,
    canThrow = false,
  ): Promise<Omit<ApiKey, 'key'> | null> {
    if ( canThrow )
      return this.prisma.apiKey.findUniqueOrThrow({
        where: apiKeyWhereUniqueInput,
        select: {
          id: true,
          application: true,
          default: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    else
      return this.prisma.apiKey.findUnique({
        where: apiKeyWhereUniqueInput,
        select: {
          id: true,
          application: true,
          default: true,
          createdAt: true,
          updatedAt: true,
        },
      });
  }

  async create({ application }: CreateApiKeyZodDto): Promise<Omit<ApiKey, 'key'>> {
    try {
      return this.prisma.apiKey.create({
        data: {
          application,
          key: require('crypto').randomBytes(64).toString('base64'),
        },
        select: {
          id: true,
          application: true,
          default: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    } catch ( e ) {
      throw new ZodValidationException(
        z.ZodError.create([
          {
            code: 'custom',
            path: [],
            message: 'Create api key failure',
          },
        ]),
      );
    }
  }

  async update(params: {
    where: Prisma.ApiKeyWhereUniqueInput;
    data: UpdateApiKeyZodDto;
  }): Promise<Omit<ApiKey, 'key'>> {
    const { where, data } = params;
    await this.prisma.apiKey.update({
      where,
      data: {
        application: data.application,
      },
    });

    if ( data?.rollApiKey )
      await this.prisma.apiKey.update({
        where,
        data: {
          key: require('crypto').randomBytes(64).toString('base64'),
        },
      });

    return this.prisma.apiKey.findUniqueOrThrow({
      where,
      select: {
        id: true,
        application: true,
        default: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  async delete(where: Prisma.ApiKeyWhereUniqueInput): Promise<ApiKey> {
    return this.prisma.apiKey.delete({ where });
  }

  async getKey(id: string) {
    return this.prisma.apiKey.findUnique({
      where: { id },
      select: { key: true },
    });
  }
}
