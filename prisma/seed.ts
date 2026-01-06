import process from 'node:process';
import { envs } from '../src/config/envs';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaPg } from '@prisma/adapter-pg';

// Crear PrismaClient
const prisma = new PrismaClient({
  adapter: new PrismaPg({
    connectionString: envs.DATABASE_URL,
  })
});

async function main() {
  /*--------------------------------------------------------------
    ##  Seeding Permissions
  ----------------------------------------------------------------*/
  console.log('🔐 Creating permissions...');

  const permissions = [
    // Users permissions
    { resource: 'users', action: 'read', identifier: 'users:read', description: 'View users' },
    { resource: 'users', action: 'write', identifier: 'users:write', description: 'Create and update users' },
    { resource: 'users', action: 'delete', identifier: 'users:delete', description: 'Delete users' },
    { resource: 'users', action: 'all', identifier: 'users:all', description: 'All actions on users' },

    // Roles permissions
    { resource: 'roles', action: 'read', identifier: 'roles:read', description: 'View roles' },
    { resource: 'roles', action: 'write', identifier: 'roles:write', description: 'Create and update roles' },
    { resource: 'roles', action: 'delete', identifier: 'roles:delete', description: 'Delete roles' },
    { resource: 'roles', action: 'all', identifier: 'roles:all', description: 'All actions on roles' },

    // Permissions management
    { resource: 'permissions', action: 'read', identifier: 'permissions:read', description: 'View permissions' },
    {
      resource: 'permissions',
      action: 'write',
      identifier: 'permissions:write',
      description: 'Assign permissions to roles',
    },
    {
      resource: 'permissions',
      action: 'all',
      identifier: 'permissions:all',
      description: 'All actions on permissions',
    },

    // API Keys permissions
    { resource: 'api-keys', action: 'read', identifier: 'api-keys:read', description: 'View API keys' },
    { resource: 'api-keys', action: 'write', identifier: 'api-keys:write', description: 'Create and update API keys' },
    { resource: 'api-keys', action: 'delete', identifier: 'api-keys:delete', description: 'Delete API keys' },
    { resource: 'api-keys', action: 'reveal', identifier: 'api-keys:reveal', description: 'View API key secrets' },
    { resource: 'api-keys', action: 'all', identifier: 'api-keys:all', description: 'All actions on api keys' },

    // Sessions permissions
    { resource: 'sessions', action: 'read', identifier: 'sessions:read', description: 'View sessions' },
    { resource: 'sessions', action: 'delete', identifier: 'sessions:delete', description: 'Delete sessions' },
    { resource: 'sessions', action: 'all', identifier: 'sessions:all', description: 'All actions on sessions' },

    // Settings permissions
    { resource: 'settings', action: 'read', identifier: 'settings:read', description: 'View settings' },
    { resource: 'settings', action: 'write', identifier: 'settings:write', description: 'Update settings' },
    { resource: 'settings', action: 'all', identifier: 'settings:all', description: 'All actions on settings' },
  ];

  for ( const permission of permissions ) {
    await prisma.permission.upsert({
      where: { identifier: permission.identifier },
      update: permission,
      create: permission,
    });
  }

  console.log(`✅ Created ${ permissions.length } permissions`);

  /*--------------------------------------------------------------
    ##  Seeding Roles (idempotent)
  ----------------------------------------------------------------*/
  console.log('👥 Creating roles...');

  await prisma.role.upsert({
    where: { identifier: 'USER_ROLE' },
    update: {
      name: 'User',
      description: 'Standard user with basic permissions',
      default: true,
    },
    create: {
      identifier: 'USER_ROLE',
      name: 'User',
      description: 'Standard user with basic permissions',
      default: true,
    },
  });

  await prisma.role.upsert({
    where: { identifier: 'ADMIN_ROLE' },
    update: {
      name: 'Admin',
      description: 'Administrator with elevated permissions',
      default: true,
    },
    create: {
      identifier: 'ADMIN_ROLE',
      name: 'Admin',
      description: 'Administrator with elevated permissions',
      default: true,
    },
  });

  await prisma.role.upsert({
    where: { identifier: 'ROOT_ROLE' },
    update: {
      name: 'Root Admin',
      description: 'Super administrator with all permissions',
      default: true,
    },
    create: {
      identifier: 'ROOT_ROLE',
      name: 'Root Admin',
      description: 'Super administrator with all permissions',
      default: true,
    },
  });

  const userRole = await prisma.role.findUniqueOrThrow({
    where: { identifier: 'USER_ROLE' },
  });
  const adminRole = await prisma.role.findUniqueOrThrow({
    where: { identifier: 'ADMIN_ROLE' },
  });
  const rootRole = await prisma.role.findUniqueOrThrow({
    where: { identifier: 'ROOT_ROLE' },
  });

  console.log('✅ Created roles');

  /*--------------------------------------------------------------
    ##  Assign Permissions to Roles
  ----------------------------------------------------------------*/
  console.log('🔗 Assigning permissions to roles...');

  // USER_ROLE: only some permissions
  const userPermissions = await prisma.permission.findMany({
    where: {
      identifier: { in: [ 'sessions:read', 'sessions:delete' ] },
    },
  });
  for ( const permission of userPermissions ) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: userRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: userRole.id,
        permissionId: permission.id,
      },
    });
  }

  // ADMIN_ROLE: wildcards for common resources
  const adminPermissionIds = await prisma.permission.findMany({
    where: {
      identifier: {
        in: [
          'users:all',
          'sessions:all',
          'settings:all',
          'roles:read',
          'roles:write',
          'roles:delete',
        ],
      },
    },
  });
  for ( const permission of adminPermissionIds ) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: adminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: adminRole.id,
        permissionId: permission.id,
      },
    });
  }

  // ROOT_ROLE: all permissions (including wildcards)
  const allPermissions = await prisma.permission.findMany();
  for ( const permission of allPermissions ) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: rootRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: rootRole.id,
        permissionId: permission.id,
      },
    });
  }

  console.log('✅ Assigned permissions to roles');

  /*--------------------------------------------------------------
    ##  Create/Upsert Root Admin User
  ----------------------------------------------------------------*/
  console.log('🧑‍💼 Creating root admin user...');

  const rootUser = await prisma.user.upsert({
    where: { email: 'root.admin@web.app' },
    update: {
      blocked: false,
      confirmed: true,
      fullName: 'Root Admin',
      username: 'root_admin',
      // Do not rotate password on upsert to keep idempotency
    },
    create: {
      email: 'root.admin@web.app',
      password: await bcrypt.hash(envs.ADMIN_PASSWORD, bcrypt.genSaltSync(16)),
      blocked: false,
      confirmed: true,
      fullName: 'Root Admin',
      username: 'root_admin',
    },
  });

  // Assign ROOT_ROLE to root admin (idempotent)
  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: rootUser.id,
        roleId: rootRole.id,
      },
    },
    update: {},
    create: {
      userId: rootUser.id,
      roleId: rootRole.id,
    },
  });

  console.log('✅ Created/updated root admin user with ROOT_ROLE');

  /*--------------------------------------------------------------
    ##  Seeding API Keys (idempotent)
  ----------------------------------------------------------------*/
  console.log('🔑 Creating API keys...');

  const apikeys = [
    { application: 'Web App', key: envs.WEB_APP_API_KEY, default: true },
    { application: 'Mobile App', key: envs.MOBILE_APP_API_KEY, default: true },
  ];
  for ( const k of apikeys ) {
    const keyHash = await bcrypt.hash(k.key, bcrypt.genSaltSync(12));
    await prisma.apiKey.upsert({
      where: { application: k.application },
      update: { keyHash, default: k.default },
      create: { application: k.application, keyHash, default: k.default },
    });
  }

  console.log('✅ Created/updated API keys');

  /*--------------------------------------------------------------
    ##  Seeding for dev (idempotent)
  ----------------------------------------------------------------*/

  if ( envs.ENVIRONMENT === 'development' ) {
    console.log('🧪 Development environment - creating test users...');

    // Create or update a test admin user
    const adminUser = await prisma.user.upsert({
      where: { email: 'admin@test.com' },
      update: {
        blocked: false,
        confirmed: true,
        fullName: 'Admin Test',
        username: 'admin_test',
      },
      create: {
        email: 'admin@test.com',
        password: await bcrypt.hash('password123', bcrypt.genSaltSync(16)),
        blocked: false,
        confirmed: true,
        fullName: 'Admin Test',
        username: 'admin_test',
      },
    });

    await prisma.userRole.upsert({
      where: {
        userId_roleId: {
          userId: adminUser.id,
          roleId: adminRole.id,
        },
      },
      update: {},
      create: {
        userId: adminUser.id,
        roleId: adminRole.id,
      },
    });

    // Create or update a test regular user
    const regularUser = await prisma.user.upsert({
      where: { email: 'user@test.com' },
      update: {
        blocked: false,
        confirmed: true,
        fullName: 'User Test',
        username: 'user_test',
      },
      create: {
        email: 'user@test.com',
        password: await bcrypt.hash('password123', bcrypt.genSaltSync(16)),
        blocked: false,
        confirmed: true,
        fullName: 'User Test',
        username: 'user_test',
      },
    });

    await prisma.userRole.upsert({
      where: {
        userId_roleId: {
          userId: regularUser.id,
          roleId: userRole.id,
        },
      },
      update: {},
      create: {
        userId: regularUser.id,
        roleId: userRole.id,
      },
    });

    console.log('✅ Created/updated test users (admin_test, user_test)');
  }

  console.log('\n🎉 Seeding completed successfully!');
}

main()
  .catch(async err => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
