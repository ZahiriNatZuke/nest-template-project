import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreateApiKeySchema = z.object({
	application: z.string().describe('Application name'),
});

export class CreateApiKeyZodDto extends createZodDto(CreateApiKeySchema) {}
