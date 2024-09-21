import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const CreateApiKeySchema = z.object({
	application: z.string().describe('Application name'),
});

export class CreateApiKeyZodDto extends createZodDto(CreateApiKeySchema) {}
