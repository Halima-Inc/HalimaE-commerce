import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  await prisma.permission.createMany({
    data: [
      { name: 'roles.read' },
      { name: 'roles.create' },
      { name: 'roles.update' },
      { name: 'roles.delete' },
    ],
    skipDuplicates: false,
  });

  await prisma.role.createMany({
    data: [
      { name: 'admin' },
      { name: 'customer' },
      { name: 'employee' },
      { name: 'manager' },
    ],
    skipDuplicates: false,
  });

  const [adminRole, rolePermissions] = await Promise.all([
    prisma.role.findFirst({ where: { name: 'admin' }, select: { id: true } }),
    prisma.permission.findMany({
      where: { name: { in: ['roles.read', 'roles.create', 'roles.update', 'roles.delete'] } },
      select: { id: true },
    }),
  ]);

  if (adminRole) {
    await prisma.rolePermission.createMany({
      data: rolePermissions.map((permission) => ({
        roleId: adminRole.id,
        permissionId: permission.id,
      })),
      skipDuplicates: false,
    });
  }

  await prisma.user.create({
    data: {
        name: 'admin',
        email: 'admin@test.com',
        passwordHash: await argon2.hash('123456789'),
        roleId: adminRole?.id,
    },
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });