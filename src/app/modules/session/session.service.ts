import { Injectable } from '@nestjs/common';
import { Prisma, Session } from '@prisma/client';
import { PrismaService } from '../../core/modules/prisma/prisma.service';

@Injectable()
export class SessionService {
  constructor(private prisma: PrismaService) {
  }

  async findMany(sessionWhereUniqueInput: Prisma.SessionWhereInput) {
    return this.prisma.session.findMany({
      where: sessionWhereUniqueInput,
    });
  }

  async findOne(
    sessionWhereUniqueInput: Prisma.SessionWhereUniqueInput,
    canThrow = false,
  ): Promise<Session | null> {
    if ( canThrow )
      return this.prisma.session.findUniqueOrThrow({
        where: sessionWhereUniqueInput,
      });
    else
      return this.prisma.session.findUnique({
        where: sessionWhereUniqueInput,
      });
  }

  async delete(where: Prisma.SessionWhereUniqueInput): Promise<Session> {
    return this.prisma.session.delete({ where });
  }
}
