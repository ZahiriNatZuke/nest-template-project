import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const AssignPermissionSchema = z.object({
	permissionId: z.uuid('Invalid permission ID format'),
});

export class AssignPermissionZodDto extends createZodDto(
	AssignPermissionSchema
) {}
