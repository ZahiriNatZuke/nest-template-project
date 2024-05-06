import { PrismaClient } from '@prisma/client';
import * as process from 'process';

const prisma = new PrismaClient();

async function main() {

}

main()
  .then(async () => await prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
