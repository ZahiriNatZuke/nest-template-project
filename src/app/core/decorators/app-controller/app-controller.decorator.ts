import { envs } from '@app/env';
import { ApiKeyAuthGuard } from '@app/modules/auth/guards';
import { Controller, UseGuards, applyDecorators } from '@nestjs/common';
import { ApiSecurity, ApiTags } from '@nestjs/swagger';

export function AppController(route: string) {
	const apiTag = route
		.split('-')
		.map(e => e.toUpperCase())
		.join(' ');
	return applyDecorators(
		Controller(route),
		UseGuards(ApiKeyAuthGuard),
		ApiTags(apiTag),
		ApiSecurity(envs.HEADER_KEY_API_KEY)
	);
}
