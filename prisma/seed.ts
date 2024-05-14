import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { envs } from '../src/config/envs';
import process from 'process';

const prisma = new PrismaClient();

async function main() {

  /*--------------------------------------------------------------
    ##  Seeding for prod
  ----------------------------------------------------------------*/

  await prisma.role.createMany({
    data: [
      {
        identifier: 'USER_ROLE',
        name: 'User',
        default: true,
      },
      {
        identifier: 'ADMIN_ROLE',
        name: 'Admin',
        default: true,
      },
      {
        identifier: 'ROOT_ROLE',
        name: 'Root Admin',
        default: true,
      },
    ],
    skipDuplicates: true,
  });

  const rootRole = await prisma.role.findUniqueOrThrow({ where: { identifier: 'ROOT_ROLE' } });

  await prisma.user.create({
    data: {
      email: 'root.admin@web.app',
      password: await bcrypt.hash(envs.ADMIN_PASSWORD, bcrypt.genSaltSync(16)),
      blocked: false,
      confirmed: true,
      fullName: 'Root Admin',
      username: 'root_admin',
      roleId: rootRole.id,
    },
  });

  await prisma.apiKey.createMany({
    data: [
      {
        application: 'Web App',
        key: envs.WEB_APP_API_KEY,
        default: true,
      },
      {
        application: 'Mobile App',
        key: envs.MOBILE_APP_API_KEY,
        default: true,
      },
    ],
    skipDuplicates: true,
  });

  /*--------------------------------------------------------------
    ##  Seeding for dev
  ----------------------------------------------------------------*/

  if ( envs.ENVIRONMENT === 'development' ) {
    // some seeds
  }
}

main()
  .then(async () => await prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
