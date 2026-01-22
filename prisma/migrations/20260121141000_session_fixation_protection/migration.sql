-- Add session fixation protection fields
ALTER TABLE "Session"
  ADD COLUMN IF NOT EXISTS "loginSessionId" TEXT,
  ADD COLUMN IF NOT EXISTS "lastActivityAt" TIMESTAMP NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS "Session_loginSessionId_idx" ON "Session"("loginSessionId");
CREATE INDEX IF NOT EXISTS "Session_lastActivityAt_idx" ON "Session"("lastActivityAt");
