import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const UpdateApiKeySchema = z.object({
	application: z.string().describe('Application name'),
	rollApiKey: z.boolean().optional(),
});

export class UpdateApiKeyZodDto extends createZodDto(UpdateApiKeySchema) {}
