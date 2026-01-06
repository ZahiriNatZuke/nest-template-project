import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreatePermissionSchema = z.object({
	resource: z.string().min(1, 'Resource is required'),
	action: z.string().min(1, 'Action is required'),
	description: z.string().optional(),
});

export class CreatePermissionZodDto extends createZodDto(
	CreatePermissionSchema
) {}
