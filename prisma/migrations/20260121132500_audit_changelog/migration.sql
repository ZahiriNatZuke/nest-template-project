CREATE TABLE IF NOT EXISTS "AuditChangeLog" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "userId" UUID NULL,
    "action" TEXT NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT NULL,
    "before" JSONB NULL,
    "after" JSONB NULL,
    "createdAt" TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "AuditChangeLog_userId_action_createdAt_idx"
    ON "AuditChangeLog"("userId", "action", "createdAt");

CREATE INDEX IF NOT EXISTS "AuditChangeLog_entity_idx"
    ON "AuditChangeLog"("entityType", "entityId");
