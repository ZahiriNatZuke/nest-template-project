import { FastifyRequest } from 'fastify';

export interface RequestInfo {
	ipAddress: string;
	userAgent: string;
}

/**
 * Extrae información de IP y User-Agent del request
 */
export function extractRequestInfo(request: FastifyRequest): RequestInfo {
	// Extraer IP - considerar proxies y headers
	const ipAddress =
		(request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
		(request.headers['x-real-ip'] as string) ||
		request.ip ||
		'unknown';

	// Extraer User-Agent
	const userAgent = (request.headers['user-agent'] as string) || 'unknown';

	return {
		ipAddress,
		userAgent,
	};
}

/**
 * Compara si dos IPs son similares (para tolerar cambios menores)
 * Ejemplo: mismo subnet (primeros 3 octetos iguales)
 */
export function isSimilarIP(ip1: string, ip2: string): boolean {
	if (ip1 === ip2) return true;
	if (ip1 === 'unknown' || ip2 === 'unknown') return false;

	// Comparar primeros 3 octetos para IPv4
	const octets1 = ip1.split('.');
	const octets2 = ip2.split('.');

	if (octets1.length === 4 && octets2.length === 4) {
		// Mismo subnet (/24)
		return (
			octets1[0] === octets2[0] &&
			octets1[1] === octets2[1] &&
			octets1[2] === octets2[2]
		);
	}

	// Para IPv6 o casos especiales, solo aceptar exacta
	return false;
}

/**
 * Compara User-Agents de forma flexible
 * Ignora diferencias menores en versiones
 */
export function isSimilarUserAgent(ua1: string, ua2: string): boolean {
	if (ua1 === ua2) return true;
	if (ua1 === 'unknown' || ua2 === 'unknown') return false;

	// Extraer info básica (browser y OS, ignorar versiones patch)
	const extractBase = (ua: string): string => {
		// Simplificar: extraer navegador principal y OS
		const browserMatch =
			ua.match(/(Chrome|Firefox|Safari|Edge|Opera)/i)?.[0] || '';
		const osMatch = ua.match(/(Windows|Mac|Linux|Android|iOS)/i)?.[0] || '';
		return `${browserMatch}/${osMatch}`.toLowerCase();
	};

	return extractBase(ua1) === extractBase(ua2);
}
