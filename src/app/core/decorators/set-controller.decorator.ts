import { applyDecorators, Controller, UseGuards } from '@nestjs/common';
import { ApiSecurity, ApiTags } from '@nestjs/swagger';
import { envs } from '../../../config/envs';
import { ApiKeyAuthGuard } from '../../modules/auth/guards/apikey-auth.guard';

export function SetController(route: string) {
  const apiTag = route
    .split('-')
    .map((e) => e.toUpperCase())
    .join(' ');
  return applyDecorators(
    Controller(route),
    UseGuards(ApiKeyAuthGuard),
    ApiTags(apiTag),
    ApiSecurity(envs.HEADER_KEY_API_KEY),
  );
}
