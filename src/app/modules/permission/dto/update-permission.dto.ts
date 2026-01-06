import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdatePermissionSchema = z.object({
	description: z.string().optional(),
});

export class UpdatePermissionZodDto extends createZodDto(
	UpdatePermissionSchema
) {}
