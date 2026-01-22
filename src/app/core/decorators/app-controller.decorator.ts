import { envs } from '@app/env';
import { applyDecorators, Controller } from '@nestjs/common';
import { ApiBearerAuth, ApiSecurity, ApiTags } from '@nestjs/swagger';

export function AppController(route: string) {
	const apiTag = route
		.split('-')
		.map(e => e.toUpperCase())
		.join(' ');
	return applyDecorators(
		Controller(route),
		ApiTags(apiTag),
		ApiBearerAuth('Authorization'),
		ApiSecurity(envs.HEADER_KEY_API_KEY)
	);
}
