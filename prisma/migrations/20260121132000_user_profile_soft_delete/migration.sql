-- Add soft delete, email confirmation/reset fields, and extended profile
ALTER TABLE "User"
  ADD COLUMN IF NOT EXISTS "resetPasswordExpiresAt" TIMESTAMP,
  ADD COLUMN IF NOT EXISTS "confirmationTokenExpiresAt" TIMESTAMP,
  ADD COLUMN IF NOT EXISTS "confirmedAt" TIMESTAMP,
  ADD COLUMN IF NOT EXISTS "deletedAt" TIMESTAMP,
  ADD COLUMN IF NOT EXISTS "avatarUrl" TEXT,
  ADD COLUMN IF NOT EXISTS "phone" TEXT,
  ADD COLUMN IF NOT EXISTS "address" TEXT,
  ADD COLUMN IF NOT EXISTS "bio" TEXT;

-- Ensure tokens columns exist (idempotent add if missing)
ALTER TABLE "User"
  ADD COLUMN IF NOT EXISTS "resetPasswordToken" TEXT,
  ADD COLUMN IF NOT EXISTS "confirmationToken" TEXT;

CREATE INDEX IF NOT EXISTS "User_deletedAt_idx" ON "User"("deletedAt");
CREATE INDEX IF NOT EXISTS "User_confirmationToken_idx" ON "User"("confirmationToken");
CREATE INDEX IF NOT EXISTS "User_resetPasswordToken_idx" ON "User"("resetPasswordToken");
