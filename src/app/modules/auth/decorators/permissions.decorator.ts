import { SetMetadata } from '@nestjs/common';
import { PERMISSIONS_METADATA_KEY } from '../guards/permissions.guard';

export const RequirePermissions = (...permissions: string[]) =>
	SetMetadata(PERMISSIONS_METADATA_KEY, permissions);
