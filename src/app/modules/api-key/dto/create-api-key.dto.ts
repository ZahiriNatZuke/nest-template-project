import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const CreateApiKeySchema = z.object({
  application: z.string().describe('Application name'),
});

// class is required for using DTO as a type
export class CreateApiKeyZodDto extends createZodDto(CreateApiKeySchema) {
}
