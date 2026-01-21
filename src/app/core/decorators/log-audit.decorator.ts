import { SetMetadata } from '@nestjs/common';

export type AuditMetadata = {
	action: string;
	entityType: string;
	entityIdParam?: string;
	omitBody?: boolean;
};

export const AUDIT_METADATA_KEY = 'audit:meta';

export const LogAudit = (meta: AuditMetadata) =>
	SetMetadata(AUDIT_METADATA_KEY, meta);
