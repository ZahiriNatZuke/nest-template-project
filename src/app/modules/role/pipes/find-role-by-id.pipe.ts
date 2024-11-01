import { RoleService } from '@app/modules/role/role.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'nestjs-zod/z';

@Injectable()
export class FindRoleByIdPipe implements PipeTransform {
	constructor(private roleService: RoleService) {}

	async transform(value: string) {
		const result = z.string().uuid('Invalid UUID').safeParse(value);
		if (!result.success)
			throw new HttpException(
				{
					message: result.error.message,
					error: result.error.errors,
				},
				HttpStatus.NOT_FOUND
			);

		try {
			return await this.roleService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Role not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
