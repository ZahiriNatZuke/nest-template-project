import { isSimilarIP, isSimilarUserAgent } from './request-info';

describe('Request Info Utils', () => {
	describe('isSimilarIP', () => {
		it('should return true for identical IPs', () => {
			expect(isSimilarIP('192.168.1.100', '192.168.1.100')).toBe(true);
		});

		it('should return true for same subnet (/24)', () => {
			expect(isSimilarIP('192.168.1.100', '192.168.1.200')).toBe(true);
			expect(isSimilarIP('10.0.0.1', '10.0.0.255')).toBe(true);
		});

		it('should return false for different subnets', () => {
			expect(isSimilarIP('192.168.1.100', '192.168.2.100')).toBe(false);
			expect(isSimilarIP('10.0.0.1', '10.0.1.1')).toBe(false);
		});

		it('should return false for unknown IPs', () => {
			expect(isSimilarIP('unknown', '192.168.1.100')).toBe(false);
			expect(isSimilarIP('192.168.1.100', 'unknown')).toBe(false);
		});

		it('should handle IPv6 addresses (exact match only)', () => {
			const ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
			expect(isSimilarIP(ipv6, ipv6)).toBe(true);
			expect(isSimilarIP(ipv6, '2001:0db8:85a3:0000:0000:8a2e:0370:7335')).toBe(
				false
			);
		});
	});

	describe('isSimilarUserAgent', () => {
		it('should return true for identical User-Agents', () => {
			const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
			expect(isSimilarUserAgent(ua, ua)).toBe(true);
		});

		it('should return true for same browser and OS with different versions', () => {
			const ua1 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
			const ua2 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0';
			expect(isSimilarUserAgent(ua1, ua2)).toBe(true);
		});

		it('should return true for Safari on Mac', () => {
			const ua1 =
				'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36';
			const ua2 =
				'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) Safari/605.1.15';
			expect(isSimilarUserAgent(ua1, ua2)).toBe(true);
		});

		it('should return false for different browsers', () => {
			const chrome =
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
			const firefox =
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Firefox/115.0';
			expect(isSimilarUserAgent(chrome, firefox)).toBe(false);
		});

		it('should return false for different OS', () => {
			const windows =
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
			const mac =
				'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0';
			expect(isSimilarUserAgent(windows, mac)).toBe(false);
		});

		it('should return false for unknown User-Agents', () => {
			const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
			expect(isSimilarUserAgent('unknown', ua)).toBe(false);
			expect(isSimilarUserAgent(ua, 'unknown')).toBe(false);
		});

		it('should handle mobile browsers', () => {
			const android1 =
				'Mozilla/5.0 (Linux; Android 13) Chrome/120.0.0.0 Mobile Safari/537.36';
			const android2 =
				'Mozilla/5.0 (Linux; Android 13) Chrome/121.0.0.0 Mobile Safari/537.36';
			expect(isSimilarUserAgent(android1, android2)).toBe(true);
		});
	});
});
