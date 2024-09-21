import { RoleService } from '@app/modules/role/role.service';
import {
	ArgumentMetadata,
	HttpStatus,
	Injectable,
	NotFoundException,
	ParseUUIDPipe,
	PipeTransform,
} from '@nestjs/common';

@Injectable()
export class FindRoleByIdPipe implements PipeTransform {
	constructor(private roleService: RoleService) {}

	transform(value: string, metadata: ArgumentMetadata) {
		return new Promise((resolve, reject) => {
			const uuidPipe = new ParseUUIDPipe({
				version: '4',
				errorHttpStatusCode: HttpStatus.BAD_REQUEST,
			});
			uuidPipe
				.transform(value, metadata)
				.then(async id => {
					try {
						const role = await this.roleService.findOne({ id }, true);
						resolve(role);
					} catch (_) {
						reject(new NotFoundException('Role not found'));
					}
				})
				.catch(() => reject(new NotFoundException('UUID not valid')));
		});
	}
}
