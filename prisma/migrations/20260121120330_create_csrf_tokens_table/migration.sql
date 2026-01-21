-- CreateTable
CREATE TABLE "CsrfToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CsrfToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CsrfToken_token_key" ON "CsrfToken"("token");

-- CreateIndex
CREATE INDEX "CsrfToken_token_expiresAt_idx" ON "CsrfToken"("token", "expiresAt");
