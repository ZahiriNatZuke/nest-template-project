import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdateApiKeySchema = z.object({
	application: z.string().describe('Application name'),
	rollApiKey: z.boolean().optional(),
});

export class UpdateApiKeyZodDto extends createZodDto(UpdateApiKeySchema) {}
