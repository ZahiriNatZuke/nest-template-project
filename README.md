# Nest Template Project

Template de backend en NestJS + Fastify + Prisma pensado para aplicaciones con requisitos de seguridad, auditoría y control de acceso avanzados. Incluye autenticación con sesiones seguras, 2FA, RBAC/ABAC, protección CSRF, throttling, logging estructurado y documentación OpenAPI lista.

## Puntos clave
- **Stack**: NestJS 11, Fastify 5, Prisma 7 (PostgreSQL), Passport (local/JWT/API key), Pino, Swagger, Zod 4, Biome, SWC.
- **Seguridad por defecto**: Helmet, rate limiting global y granular (decoradores), CORS con lista blanca, API Keys, validación Zod, CSRF, mitigación de session fixation, límites de sesiones concurrentes, tokens en cookies HttpOnly.
- **Autenticación y sesiones**: Login/password, refresh tokens, cierre de sesión, recuperación y reset de password, confirmación de correo, remember-me, login attempts tracking, 2FA TOTP con códigos de respaldo.
- **Autorización avanzada**: RBAC con jerarquías de roles, permisos temporales, ABAC por políticas, ownership de recursos y guardas reutilizables (JWT, permisos, resource-owner, ABAC).
- **Auditoría y observabilidad**: Auditoría de acciones y cambios (audit log + change log), correlación de requests, logger Pino a consola y archivos rotados, interceptores y filtros globales de errores.
- **Módulos incluidos**: Auth, User, Role, Permission, Session, Api-Key, Audit-Log, Settings, Health, más servicios core (CSRF, login attempts, notification port, security alerts, 2FA, policy engine).
- **Calidad**: 315 tests unitarios y 153 e2e contra PostgreSQL real —sin módulos sin cobertura—, CI en GitHub Actions, imagen Docker multi-stage.
- **OpenAPI**: Swagger con bearer y API Key en `/swagger`, prefijo global `api/v1`.

## Requisitos
- Node.js 22+
- pnpm — la versión está fijada en el campo `packageManager`, así que basta con tener [corepack](https://nodejs.org/api/corepack.html) habilitado (`corepack enable`). No la instales aparte: el proyecto, la CI y la imagen Docker deben usar exactamente la misma.
- PostgreSQL 17 (o compatible)

## Configuración rápida

1) Clona el repositorio y copia la plantilla de entorno:

```bash
cp .env.template .env
```

Rellena al menos `DATABASE_URL`, los tres secretos JWT, `ENCRYPTION_SECRET` (mínimo 32 caracteres) y las API keys. La aplicación **no arranca** si falta alguna variable requerida: se validan con Zod al inicio.

2) Instala dependencias y genera el cliente Prisma:

```bash
pnpm install
pnpm prisma generate
```

3) Aplica migraciones y (opcional) el seed inicial:

```bash
pnpm prisma migrate dev
pnpm prisma db seed
```

4) Arranca la API:

```bash
pnpm start:dev
```

Swagger queda en `http://localhost:3000/swagger` y la API en `http://localhost:3000/api/v1` (ajusta `PORT`/`HOST`).

## Tests

```bash
pnpm test          # unitarios
pnpm test:ci       # unitarios con cobertura, en serie
pnpm test:e2e      # end to end contra PostgreSQL real
pnpm typecheck     # obligatorio: @swc/jest quita los tipos sin comprobarlos
```

Los e2e necesitan PostgreSQL en el **puerto 5433** con la base `nest_template_test`, que es lo que declara `.env.test`. La forma más corta de levantarlo:

```bash
docker compose -f docker-compose.test.yml up -d
pnpm prisma migrate deploy
pnpm test:e2e
docker compose -f docker-compose.test.yml down -v
```

`DATABASE_URL` tiene que apuntar a esa base al aplicar las migraciones; `.env.test` ya la trae.

## Docker

```bash
docker compose up --build
```

Levanta la API junto a su PostgreSQL. Requiere un `.env` en la raíz.

Los puertos publicados por defecto son 5432 y 3000, que chocan con cualquier cosa que ya esté escuchando. Sobrescríbelos en lugar de parar lo que tengas corriendo:

```bash
POSTGRES_PORT=5434 PORT=3100 docker compose up --build
```

La imagen arranca con `node dist/src/main` directamente — sin gestor de paquetes ni descargas en el arranque. Las migraciones son opcionales: con `MIGRATE_ON_BOOT=true` el entrypoint las aplica antes de servir tráfico, lo cual es correcto cuando un solo contenedor es dueño de la base. Con varias réplicas, ejecútalas como paso aparte:

```bash
pnpm run migrate:deploy
```

## Estructura relevante
- `src/main.ts` y `src/bootstrap/configure-app.ts`: bootstrap Fastify, Helmet, rate limit, CORS, Swagger, filtros y pipes globales (Zod), logger Pino. La configuración vive en `configureApp()` para que los tests e2e levanten exactamente la misma aplicación.
- `src/app.module.ts`: registro de módulos de dominio, interceptores de auditoría, throttling global y filtros.
- `src/app/core/*`: middlewares (correlation-id, request context, API key), filtros, pipes, decoradores de seguridad, servicios transversales (audit, csrf, encryption, login-attempt, notification, policy-engine, resource-ownership, role-hierarchy, security-alert, tasks, two-factor).
- `src/app/modules/*`:
  - `auth`: controladores organizados por dominio:
    - `session.controller.ts`: login/logout/refresh/CSRF
    - `profile.controller.ts`: me, permissions/me, update-password
    - `password-recovery.controller.ts`: forgot-password, reset-password, confirm-email, recovery-account
    - `two-factor.controller.ts`: setup, enable, verify, disable, regenerate-backup-codes, require/optional 2FA
  - `user`: CRUD con paginación/búsqueda, asignación de roles, borrado/restauración soft.
  - `role` / `permission`: administración de roles, jerarquías, permisos y expiraciones.
  - `session`: sesiones concurrentes, cierre y blacklist de tokens.
  - `api-key`: administración de API Keys hasheadas.
  - `audit-log`: consulta de auditoría.
  - `settings`: KV de configuración dinámica.
  - `health`: checks para liveness/readiness.
- `prisma/schema.prisma`: modelos de usuarios, roles/permisos/ABAC, sesiones, API keys, auditoría, CSRF, intentos de login, 2FA.

## Scripts útiles
- `pnpm start:dev`: desarrollo con SWC watch.
- `pnpm build` / `pnpm start:prod`: compila a `dist/` y arranca el proceso compilado.
- `pnpm migrate:deploy`: aplica migraciones (paso de despliegue, separado del arranque).
- `pnpm lint`, `pnpm format`: Biome con `--fix`. **CI usa `biome ci`**, que es de solo lectura y falla en vez de corregir.

## Seguridad y buenas prácticas incluidas
- Cookies HttpOnly para tokens, SameSite=Strict y `Secure` en producción.
- Protección CSRF (`/auth/csrf`), rate limiting global y por endpoint (decoradores `Strict/Moderate/LenientThrottle`).
- Contraseñas y API keys con bcrypt en un único work factor compartido (`BCRYPT_COST`).
- Secretos TOTP cifrados en reposo con AES-256-GCM; los códigos de respaldo se hashean y salen de un CSPRNG.
- Auditoría automática mediante decorador `@LogAudit` y `AuditInterceptor`.
- Guards reutilizables: `JwtAuthGuard`, `PermissionsGuard`, `ResourceOwnerGuard`, `AbacGuard`, `CsrfGuard`, `VerifyJwtGuard`.
- Sanitización y validación con Zod (pipes/filtros personalizados).

## Notas de comportamiento

Decisiones fijadas por test, para que un cambio futuro sea deliberado:

- **Los permisos se leen del claim `perm` del JWT**, que se rellena al iniciar sesión y resuelve la jerarquía de roles. Un permiso concedido después no surte efecto hasta el siguiente login.
- **Un login con contraseña corta devuelve 401, no 400**: los guards corren antes que los pipes, así que el mensaje de validación de Zod nunca llega al cliente.
- **`LoginAttemptService` hace fail-open** ante un error de base de datos: una caída no deja a todo el mundo fuera.
- **La auditoría es fire-and-forget**: el interceptor no bloquea la respuesta, así que un proceso que muera justo después de responder pierde el registro.
- **Una política ABAC con lista de condiciones vacía concede acceso** (semántica de `Array.every`).
- **`transferOwnership` no es transaccional**: si falla entre el revoke y el grant, el recurso se queda sin dueño.

## Limitaciones conocidas
- Las notificaciones y alertas de seguridad se entregan a través de `NotificationPort`, cuya única implementación registra por log. Cambia el `useClass` por tu proveedor al adoptar el template.
- La imagen de runtime ronda los 300 MB; los engines de Prisma dominan el tamaño.
- TypeScript está fijado por debajo de la 6 en Dependabot, y el bloqueo no está en este repositorio. Medido contra 6.0.3 y 7.0.2: `@prisma/client/index.d.ts` es un `export * from '.prisma/client/default'` que ninguno de los dos compiladores resuelve, así que el módulo sale vacío y `PrismaService` pierde todos sus delegados — unos 296 errores repartidos por casi todos los servicios, que ninguna opción de `tsconfig` corrige. Los ajustes de configuración (quitar `baseUrl`, `paths` con `./`, `"types": ["node", "jest"]`, dos bindings de `catch`) son la parte fácil. Revisar cuando Prisma publique un cliente que resuelva bajo los compiladores nuevos.

## Deploy
- Compila (`pnpm build`), aplica migraciones (`pnpm migrate:deploy`) y arranca (`pnpm start:prod`). Con Docker, `MIGRATE_ON_BOOT=true` hace el segundo paso por ti.
- Asegura variables de entorno productivas, orígenes CORS configurados y claves secretas robustas.
- Los logs rotan en `./logs` por día con compresión gzip (ver configuración en `LoggerModule`).
