import {
	createCipheriv,
	createDecipheriv,
	randomBytes,
	scrypt,
} from 'node:crypto';
import { promisify } from 'node:util';
import { envs } from '@app/env';
import { Injectable, Logger } from '@nestjs/common';

const scryptAsync = promisify(scrypt);

/**
 * Service for encrypting and decrypting sensitive data
 * Uses AES-256-GCM for encryption
 */
@Injectable()
export class EncryptionService {
	private readonly logger = new Logger(EncryptionService.name);
	private readonly algorithm = 'aes-256-gcm';
	private readonly keyLength = 32; // 256 bits
	private readonly ivLength = 16; // 128 bits
	private readonly saltLength = 16;

	/**
	 * Derive encryption key from password using scrypt
	 */
	private async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
		return (await scryptAsync(password, salt, this.keyLength)) as Buffer;
	}

	/**
	 * Encrypt data using AES-256-GCM
	 * @param data - Data to encrypt (will be stringified if object)
	 * @returns Encrypted data in format: salt:iv:tag:encryptedData (base64)
	 */
	async encrypt(data: string | object): Promise<string> {
		try {
			const textToEncrypt =
				typeof data === 'string' ? data : JSON.stringify(data);

			// Generate random salt and IV
			const salt = randomBytes(this.saltLength);
			const iv = randomBytes(this.ivLength);

			// Derive key from encryption secret
			const key = await this.deriveKey(envs.ENCRYPTION_SECRET, salt);

			// Create cipher
			const cipher = createCipheriv(this.algorithm, key, iv);

			// Encrypt data
			let encrypted = cipher.update(textToEncrypt, 'utf8', 'base64');
			encrypted += cipher.final('base64');

			// Get authentication tag
			const tag = cipher.getAuthTag();

			// Combine salt:iv:tag:encryptedData
			return `${salt.toString('base64')}:${iv.toString('base64')}:${tag.toString('base64')}:${encrypted}`;
		} catch (error) {
			this.logger.error('Encryption failed', error);
			throw new Error('Failed to encrypt data');
		}
	}

	/**
	 * Decrypt data encrypted with encrypt()
	 * @param encryptedData - Encrypted data in format: salt:iv:tag:encryptedData (base64)
	 * @returns Decrypted data (string)
	 */
	async decrypt(encryptedData: string): Promise<string> {
		try {
			// Split the encrypted data
			const parts = encryptedData.split(':');
			if (parts.length !== 4) {
				throw new Error('Invalid encrypted data format');
			}

			const [saltB64, ivB64, tagB64, encrypted] = parts;

			// Convert from base64
			const salt = Buffer.from(saltB64, 'base64');
			const iv = Buffer.from(ivB64, 'base64');
			const tag = Buffer.from(tagB64, 'base64');

			// Derive key
			const key = await this.deriveKey(envs.ENCRYPTION_SECRET, salt);

			// Create decipher
			const decipher = createDecipheriv(this.algorithm, key, iv);
			decipher.setAuthTag(tag);

			// Decrypt data
			let decrypted = decipher.update(encrypted, 'base64', 'utf8');
			decrypted += decipher.final('utf8');

			return decrypted;
		} catch (error) {
			this.logger.error('Decryption failed', error);
			throw new Error('Failed to decrypt data');
		}
	}

	/**
	 * Encrypt an object and return encrypted string
	 */
	async encryptObject<T>(obj: T): Promise<string> {
		return this.encrypt(JSON.stringify(obj));
	}

	/**
	 * Decrypt a string and parse it as JSON object
	 */
	async decryptObject<T>(encryptedData: string): Promise<T> {
		const decrypted = await this.decrypt(encryptedData);
		return JSON.parse(decrypted) as T;
	}

	/**
	 * Check if data is encrypted (has the expected format)
	 */
	isEncrypted(data: string): boolean {
		const parts = data.split(':');
		return parts.length === 4;
	}
}
