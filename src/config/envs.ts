import 'dotenv/config';
import { z } from 'zod';
import process from 'node:process';

const envsSchema = z.object({
  ENVIRONMENT: z.string().default('development'),
  DATABASE_URL: z.string(),
  DATABASE_PROVIDER: z.string(),
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default('localhost'),
  ORIGINS: z.string().transform((origins) => origins.split(',')),
  RATE_LIMIT_WINDOWS: z.coerce.number(),
  RATE_LIMIT_MAX: z.coerce.number(),
  JWT_SECRET: z.string(),
  EXPIRESIN_ACCESS: z.string(),
  JWT_VERIFICATION_TOKEN_SECRET: z.string(),
  JWT_VERIFICATION_TOKEN_EXPIRATION_TIME: z.string(),
  JWT_REFRESH_TOKEN_SECRET: z.string(),
  EXPIRESIN_REFRESH: z.string(),
  EMAIL_CONFIRMATION_URL: z.string(),
  RECOVERY_ACCOUNT_URL: z.string(),
  ADMIN_PASSWORD: z.string(),
  SWAGGER_VERSION: z
    .string()
    .default('1.0.0')
    .transform(() => process.env.npm_package_version || '1.0.0'),
  APP_NAME: z.string(),
  MAIL_USER: z.string(),
  MAIL_FROM: z.string(),
  HEADER_KEY_API_KEY: z.string(),
  WEB_APP_API_KEY: z.string(),
  MOBILE_APP_API_KEY: z.string(),
  PINO_LOG_LEVEL: z.string(),
});

export const envs = envsSchema.parse(process.env);
