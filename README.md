# Nest Template Project

Template de backend en NestJS + Fastify + Prisma pensado para aplicaciones con requisitos de seguridad, auditoría y control de acceso avanzados. Incluye autenticación con sesiones seguras, 2FA, RBAC/ABAC, protección CSRF, throttling, logging estructurado y documentación OpenAPI lista.

## Puntos clave
- **Stack**: NestJS 11, Fastify 5, Prisma ORM (PostgreSQL), Passport (local/JWT), Pino, Swagger, Biome, SWC.
- **Seguridad por defecto**: Helmet, rate limiting global y granular (decoradores), CORS con lista blanca, API Keys, validación Zod, CSRF, mitigación de session fixation, límites de sesiones concurrentes, tokens en cookies HttpOnly.
- **Autenticación y sesiones**: Login/password, refresh tokens, cierre de sesión, recuperación y reset de password, confirmación de correo, remember-me, login attempts tracking, 2FA TOTP con códigos de respaldo.
- **Autorización avanzada**: RBAC con jerarquías de roles, permisos temporales, ABAC por políticas, ownership de recursos y guardas reutilizables (JWT, permisos, resource-owner, ABAC).
- **Auditoría y observabilidad**: Auditoría de acciones y cambios (audit log + change log), correlación de requests, logger Pino a consola y archivos rotados, interceptores y filtros globales de errores.
- **Módulos incluidos**: Auth, User, Role, Permission, Session, Api-Key, Audit-Log, Settings, Health, más servicios core (CSRF, login attempts, notification stub, security alerts, 2FA, policy engine).
- **OpenAPI**: Swagger con bearer y API Key en `/swagger`, prefijo global `api/v1`.

## Requisitos
- Node.js 20+
- pnpm 9+
- PostgreSQL 14+ (o compatible)

## Configuración rápida
1) Clona el repositorio y copia un archivo `.env` usando este ejemplo:

```env
ENVIRONMENT=development
APP_NAME=Nest Template Project
PORT=3000
HOST=localhost
ORIGINS=http://localhost:3000,http://localhost:5173
DATABASE_URL=postgresql://user:pass@localhost:5432/nest_template
DATABASE_PROVIDER=postgresql
RATE_LIMIT_WINDOWS=60000
RATE_LIMIT_MAX=100
JWT_SECRET=change_me
EXPIRESIN_ACCESS=15m
JWT_VERIFICATION_TOKEN_SECRET=change_me_verification
JWT_VERIFICATION_TOKEN_EXPIRATION_TIME=15m
JWT_REFRESH_TOKEN_SECRET=change_me_refresh
EXPIRESIN_REFRESH=7d
EMAIL_CONFIRMATION_URL=http://localhost:3000/confirm
RECOVERY_ACCOUNT_URL=http://localhost:3000/recovery
ADMIN_PASSWORD=change_me
HEADER_KEY_API_KEY=X-API-KEY
WEB_APP_API_KEY=demo-web-key
MOBILE_APP_API_KEY=demo-mobile-key
PINO_LOG_LEVEL=info
MAX_CONCURRENT_SESSIONS=5
ENCRYPTION_SECRET=32_chars_minimum________________________________
MAIL_USER=no-reply@example.com
MAIL_FROM=No Reply <no-reply@example.com>
SWAGGER_VERSION=1.0.0
```

2) Instala dependencias:
```bash
pnpm install
```

3) Genera cliente Prisma, corre migraciones y (opcional) seed inicial:
```bash
pnpm prisma generate
pnpm prisma migrate dev --name init
pnpm prisma db seed
```

4) Arranca la API:
```bash
pnpm start:dev
```

Swagger quedará en `http://localhost:3000/swagger` y el API en `http://localhost:3000/api/v1` (ajusta `PORT`/`HOST`).

## Estructura relevante
- `src/main.ts`: bootstrap Fastify, Helmet, rate limit, CORS, Swagger, filtros y pipes globales (Zod), logger Pino.
- `src/app.module.ts`: registro de módulos de dominio, interceptores de auditoría, throttling global y filtros.
- `src/app/core/*`: middlewares (correlation-id, request context, API key), filtros, pipes, decoradores de seguridad, servicios transversales (audit, csrf, login-attempt, notification, policy-engine, resource-ownership, role-hierarchy, security-alert, tasks, two-factor).
- `src/app/modules/*`:
  - `auth`: controladores modulares organizados por dominio:
    - `session.controller.ts`: login/logout/refresh/CSRF
    - `profile.controller.ts`: me, permissions/me, update-password
    - `password-recovery.controller.ts`: forgot-password, reset-password, confirm-email, recovery-account
    - `two-factor.controller.ts`: setup, enable, verify, disable, regenerate-backup-codes, require/optional 2FA
  - `user`: CRUD con paginación/búsqueda, asignación de roles, borrado/restauración soft.
  - `role` / `permission`: administración de roles, jerarquías, permisos y expiraciones.
  - `session`: sesiones concurrentes, cierre y blacklist de tokens.
  - `api-key`: administración de API Keys hashadas.
  - `audit-log`: consulta de auditoría.
  - `settings`: KV de configuración dinámica.
  - `health`: checks para liveness/readiness.
- `prisma/schema.prisma`: modelos de usuarios, roles/permisos/ABAC, sesiones, API keys, auditoría, CSRF, intentos de login, 2FA.

## Scripts útiles
- `pnpm start:dev`: desarrollo con SWC watch.
- `pnpm start:prod`: requiere build + `prisma migrate deploy` (usado en `prestart:prod`).
- `pnpm build`: compila a `dist/`.
- `pnpm test`, `pnpm test:cov`, `pnpm test:e2e`: comandos disponibles (no hay suites en el repo actualmente).
- `pnpm lint`, `pnpm format`: chequeo y formato con Biome.

## Seguridad y buenas prácticas incluidas
- Cookies HttpOnly para tokens, SameSite=Strict y `Secure` en producción.
- Protección CSRF (`/auth/csrf`), rate limiting global y por endpoint (decoradores `Strict/Moderate/LenientThrottle`).
- Auditoría automática mediante decorador `@LogAudit` y `AuditInterceptor`.
- Guards reutilizables: `JwtAuthGuard`, `PermissionsGuard`, `ResourceOwnerGuard`, `AbacGuard`, `CsrfGuard`, `VerifyJwtGuard`.
- Sanitización y validación con Zod (pipes/filtros personalizados).

## Mejoras recientes
- ✅ **Controlador de autenticación modularizado**: El controlador monolítico `auth.controller.ts` (~900 líneas) ha sido dividido en 4 controladores especializados para mejorar mantenibilidad y facilitar testing:
  - `SessionController`: gestión de sesiones (login, logout, refresh, CSRF)
  - `ProfileController`: perfil de usuario (me, permisos, cambio de password)
  - `PasswordRecoveryController`: recuperación de cuentas y passwords
  - `TwoFactorController`: configuración y verificación de 2FA

## Pendientes/limitaciones detectadas
- No se incluyen pruebas unitarias o e2e en el repositorio; los comandos están pero necesitarán suites.
- Las rutas de notificación/alertas de seguridad están stub para que se integre el proveedor deseado al usar el template.

## Deploy
- Para despliegue, usa `pnpm run prestart:prod` (aplica migraciones) y luego `pnpm start:prod`.
- Asegura variables de entorno productivas, origenes CORS configurados y claves secretas robustas.
- Los logs rotan en `./logs` por día con compresión gzip (ver configuración en `LoggerModule`).
