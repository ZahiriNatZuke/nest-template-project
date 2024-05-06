import { applyDecorators, Controller } from '@nestjs/common';
import { ApiSecurity, ApiTags } from '@nestjs/swagger';

export function SetController(route: string) {
  const apiTag = route
    .split('-')
    .map((e) => e.toUpperCase())
    .join(' ');
  return applyDecorators(
    Controller(route),
    // UseGuards(ApiKeyAuthGuard),
    ApiTags(apiTag),
    ApiSecurity(<string>process.env[ 'HEADER_KEY_API_KEY' ]),
  );
}
