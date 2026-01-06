import { Pagination } from '@app/core/types/interfaces/pagination';
import {
	applyDecorators,
	createParamDecorator,
	ExecutionContext,
} from '@nestjs/common';
import { ApiQuery } from '@nestjs/swagger';
import { FastifyRequest } from 'fastify';

export const PaginationDecorator = createParamDecorator(
	(_data, ctx: ExecutionContext): Pagination => {
		const req: FastifyRequest & { query: Pagination } = ctx
			.switchToHttp()
			.getRequest();

		const { take, page } = req.query;
		return {
			url: req.url.split('?')[0],
			take: take ? (+take <= 0 ? 10 : +take) : 10,
			page: page ? (+page <= 0 ? 1 : +page) : 1,
		};
	}
);

export function ApiPaginationDecorator() {
	return applyDecorators(
		ApiQuery({ name: 'take', type: 'integer', required: false }),
		ApiQuery({ name: 'page', type: 'integer', required: false })
	);
}
