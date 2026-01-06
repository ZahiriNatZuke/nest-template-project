import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { Prisma, Session } from '@prisma/client';

@Injectable()
export class SessionService {
	constructor(private prisma: PrismaService) {}

	async findMany(sessionWhereUniqueInput: Prisma.SessionWhereInput) {
		return this.prisma.session.findMany({
			where: sessionWhereUniqueInput,
		});
	}

	async findOne(
		sessionWhereUniqueInput: Prisma.SessionWhereUniqueInput,
		canThrow = false
	): Promise<Session | null> {
		if (canThrow)
			return this.prisma.session.findUniqueOrThrow({
				where: sessionWhereUniqueInput,
			});

		return this.prisma.session.findUnique({
			where: sessionWhereUniqueInput,
		});
	}

	async delete(where: Prisma.SessionWhereUniqueInput): Promise<Session> {
		return this.prisma.session.delete({ where });
	}
}
