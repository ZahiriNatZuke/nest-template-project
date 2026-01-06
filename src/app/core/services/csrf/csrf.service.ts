import { randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';

@Injectable()
export class CsrfService {
	private tokens = new Map<string, { token: string; expiresAt: number }>();

	generateToken(): string {
		const token = randomBytes(32).toString('hex');
		const expiresAt = Date.now() + 1000 * 60 * 60; // 1 hour
		this.tokens.set(token, { token, expiresAt });
		return token;
	}

	validateToken(token: string): boolean {
		const entry = this.tokens.get(token);
		if (!entry) return false;
		if (entry.expiresAt < Date.now()) {
			this.tokens.delete(token);
			return false;
		}
		return true;
	}

	invalidateToken(token: string): void {
		this.tokens.delete(token);
	}

	// Cleanup expired tokens every 10 minutes
	constructor() {
		setInterval(
			() => {
				const now = Date.now();
				for (const [token, entry] of this.tokens.entries()) {
					if (entry.expiresAt < now) {
						this.tokens.delete(token);
					}
				}
			},
			10 * 60 * 1000
		);
	}
}
