/**
 * Configuración de rutas públicas y protegidas
 * Define qué endpoints requieren autenticación y cuáles son públicos
 */

/**
 * Rutas públicas que NO requieren autenticación
 * Accesibles sin JWT o API Key
 */
export const PUBLIC_ROUTES = [
	'/api/v1/health',
	'/api/v1/health/liveness',
	'/api/v1/health/readiness',
	'/api/v1/auth/login',
	'/api/v1/auth/refresh',
	'/api/v1/auth/csrf',
	'/api/v1/auth/confirm-email',
	'/api/v1/auth/forgot-password',
	'/api/v1/auth/reset-password',
	'/api/v1/auth/request-recovery-account',
	'/api/v1/auth/recovery-account',
];

/**
 * Rutas protegidas que requieren JWT
 * Accesibles solo con token JWT válido
 */
export const JWT_PROTECTED_ROUTES = [
	'/api/v1/auth/me',
	'/api/v1/auth/logout',
	'/api/v1/auth/permissions/me',
	'/api/v1/auth/update-password',
	'/api/v1/auth/2fa',
	'/api/v1/user',
	'/api/v1/role',
	'/api/v1/permission',
	'/api/v1/settings',
];

/**
 * Rutas que requieren API Key o JWT
 * Accesibles con API Key para integración o JWT para usuarios autenticados
 */
export const API_KEY_OR_JWT_ROUTES = ['/api/v1/audit-log', '/api/v1/api-key'];

/**
 * Verifica si una ruta está en la lista de rutas públicas
 */
export function isPublicRoute(path: string): boolean {
	return PUBLIC_ROUTES.some(route => path.startsWith(route));
}

/**
 * Verifica si una ruta está protegida por JWT
 */
export function isJwtProtectedRoute(path: string): boolean {
	return JWT_PROTECTED_ROUTES.some(route => path.startsWith(route));
}

/**
 * Verifica si una ruta acepta API Key o JWT
 */
export function isApiKeyOrJwtRoute(path: string): boolean {
	return API_KEY_OR_JWT_ROUTES.some(route => path.startsWith(route));
}

/**
 * Verifica si una ruta requiere autenticación
 */
export function requiresAuthentication(path: string): boolean {
	return !isPublicRoute(path);
}
