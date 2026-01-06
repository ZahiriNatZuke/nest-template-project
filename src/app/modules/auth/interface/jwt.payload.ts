export interface JWTPayload {
	userId: string;
	fullName: string;
	email: string;
	device: string;
	perm?: string[]; // cached permissions identifiers
}
