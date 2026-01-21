-- AlterTable
ALTER TABLE "Role" ADD COLUMN     "parentRoleId" TEXT;

-- AlterTable
ALTER TABLE "RolePermission" ADD COLUMN     "expiresAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "Policy" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "description" TEXT,
    "roleId" TEXT NOT NULL,
    "condition" JSONB NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ResourceOwnership" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "accessLevel" TEXT NOT NULL DEFAULT 'owner',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ResourceOwnership_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Policy_identifier_key" ON "Policy"("identifier");

-- CreateIndex
CREATE INDEX "Policy_roleId_idx" ON "Policy"("roleId");

-- CreateIndex
CREATE INDEX "Policy_active_idx" ON "Policy"("active");

-- CreateIndex
CREATE INDEX "ResourceOwnership_userId_resourceType_idx" ON "ResourceOwnership"("userId", "resourceType");

-- CreateIndex
CREATE INDEX "ResourceOwnership_resourceType_resourceId_idx" ON "ResourceOwnership"("resourceType", "resourceId");

-- CreateIndex
CREATE UNIQUE INDEX "ResourceOwnership_userId_resourceType_resourceId_key" ON "ResourceOwnership"("userId", "resourceType", "resourceId");

-- CreateIndex
CREATE INDEX "Role_parentRoleId_idx" ON "Role"("parentRoleId");

-- CreateIndex
CREATE INDEX "RolePermission_expiresAt_idx" ON "RolePermission"("expiresAt");

-- AddForeignKey
ALTER TABLE "Role" ADD CONSTRAINT "Role_parentRoleId_fkey" FOREIGN KEY ("parentRoleId") REFERENCES "Role"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;
