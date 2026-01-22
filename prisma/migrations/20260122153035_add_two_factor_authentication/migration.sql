/*
  Warnings:

  - The primary key for the `AuditChangeLog` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- AlterTable
ALTER TABLE "AuditChangeLog" DROP CONSTRAINT "AuditChangeLog_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ALTER COLUMN "createdAt" SET DATA TYPE TIMESTAMP(3),
ADD CONSTRAINT "AuditChangeLog_pkey" PRIMARY KEY ("id");

-- AlterTable
ALTER TABLE "Session" ALTER COLUMN "lastActivityAt" SET DATA TYPE TIMESTAMP(3);

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "twoFactorBackupCodes" JSONB,
ADD COLUMN     "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "twoFactorSecret" TEXT,
ALTER COLUMN "resetPasswordExpiresAt" SET DATA TYPE TIMESTAMP(3),
ALTER COLUMN "confirmationTokenExpiresAt" SET DATA TYPE TIMESTAMP(3),
ALTER COLUMN "confirmedAt" SET DATA TYPE TIMESTAMP(3),
ALTER COLUMN "deletedAt" SET DATA TYPE TIMESTAMP(3);

-- CreateTable
CREATE TABLE "TwoFactorAttempt" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "success" BOOLEAN NOT NULL DEFAULT false,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TwoFactorAttempt_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TwoFactorAttempt_userId_createdAt_idx" ON "TwoFactorAttempt"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "TwoFactorAttempt_success_createdAt_idx" ON "TwoFactorAttempt"("success", "createdAt");

-- AddForeignKey
ALTER TABLE "TwoFactorAttempt" ADD CONSTRAINT "TwoFactorAttempt_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- RenameIndex
ALTER INDEX "AuditChangeLog_entity_idx" RENAME TO "AuditChangeLog_entityType_entityId_idx";
