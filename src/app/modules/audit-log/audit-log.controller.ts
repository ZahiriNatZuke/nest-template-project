import { AppController } from '@app/core/decorators/app-controller.decorator';
import {
	ApiPaginationDecorator,
	PaginationDecorator,
} from '@app/core/decorators/pagination.decorator';
import { TrimQuerySearchPipe } from '@app/core/pipes/trim-query-search.pipe';
import { AuditService } from '@app/core/services/audit/audit.service';
import { Pagination } from '@app/core/types/pagination';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { Get, HttpStatus, Query, Res } from '@nestjs/common';
import { ApiQuery } from '@nestjs/swagger';
import { FastifyReply } from 'fastify';

@AppController('audit-log')
export class AuditLogController {
	constructor(private auditService: AuditService) {}

	@Get()
	@Authz('audit:read')
	@ApiQuery({ name: 'action', required: false })
	@ApiQuery({ name: 'entityType', required: false })
	@ApiQuery({ name: 'userId', required: false })
	@ApiPaginationDecorator()
	async findMany(
		@Res() res: FastifyReply,
		@PaginationDecorator() pagination: Pagination,
		@Query('action', TrimQuerySearchPipe) action?: string,
		@Query('entityType', TrimQuerySearchPipe) entityType?: string,
		@Query('userId', TrimQuerySearchPipe) userId?: string
	) {
		const { take, page, url } = pagination;
		const [total, items] = await this.auditService.findManyPaged({
			take,
			skip: (page - 1) * take,
			action,
			entityType,
			userId,
		});
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: items,
			meta: {
				total,
				page,
				take,
				url,
			},
		});
	}
}
