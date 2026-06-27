import { INestApplication, LoggerService } from '@nestjs/common';
import request from 'supertest';
import * as argon2 from 'argon2';
import { PrismaService } from '../src/prisma/prisma.service';
import {
    setupE2ETest,
    teardownE2ETest,
    getUniqueTestData,
} from './jest-e2e.setup';
import { LogService } from '../src/common/log.service';
import {
    expectSuccessResponse,
    expectErrorResponse,
    extractAuthTokenFromResponse,
} from './test-utils';

describe('CategoryController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let adminToken: string;
    let employeeToken: string;
    let adminRoleId: string;
    let employeeRoleId: string;
    let logger: LoggerService;

    // Store created category IDs to clean up
    const categoryIds: string[] = [];

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());
        logger = app.get<LoggerService>(LogService);

        // Seed roles
        const [adminRole, employeeRole] = await Promise.all([
            prisma.role.create({ data: { name: 'admin' } }),
            prisma.role.create({ data: { name: 'employee' } }),
        ]);

        adminRoleId = adminRole.id;
        employeeRoleId = employeeRole.id;

        // Create admin user
        const adminData = getUniqueTestData('cat-admin');
        await prisma.user.create({
            data: {
                email: adminData.email,
                name: adminData.name,
                passwordHash: await argon2.hash('password123'),
                roleId: adminRoleId,
            },
        });

        // Create employee user
        const employeeData = getUniqueTestData('cat-employee');
        await prisma.user.create({
            data: {
                email: employeeData.email,
                name: employeeData.name,
                passwordHash: await argon2.hash('password123'),
                roleId: employeeRoleId,
            },
        });

        // Login admin
        const adminLogin = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: adminData.email, password: 'password123' })
            .expect(200);
        adminToken = extractAuthTokenFromResponse(adminLogin);

        // Login employee
        const employeeLogin = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: employeeData.email, password: 'password123' })
            .expect(200);
        employeeToken = extractAuthTokenFromResponse(employeeLogin);
    }, 30000); // Set timeout to 30 seconds for setup

    afterAll(async () => {
        if (app && prisma) {
            await teardownE2ETest(app, prisma);
        }
    }, 60000); // Set timeout to 60 seconds for teardown

    describe('/categories (POST)', () => {
        it('should reject creation for unauthenticated user', () => {
            return request(app.getHttpServer())
                .post('/api/categories')
                .send({ name: "Women's Clothing", slug: 'womens-clothing' })
                .expect(401)
                .expect((res) => {
                    expectErrorResponse(res, 401);
                });
        });

        it('should create a new top-level category for an admin user', async () => {
            const dto = { name: "Women's Clothing", slug: 'womens-clothing' };
            const response = await request(app.getHttpServer())
                .post('/api/categories')
                .set('Authorization', `Bearer ${adminToken}`)
                .send(dto)
                .expect(201);

            const data = expectSuccessResponse<any>(response, 201);
            expect(data).toMatchObject(dto);
            expect(data.id).toBeDefined();
            categoryIds.push(data.id);
        });

        it('should create a new sub-category for an employee user', async () => {
            const parentCategory = await prisma.category.findUnique({
                where: { slug: 'womens-clothing' },
            });
            expect(parentCategory).not.toBeNull();
            const dto = {
                name: 'Dresses',
                slug: 'dresses',
                parentId: parentCategory!.id,
            };

            const response = await request(app.getHttpServer())
                .post('/api/categories')
                .set('Authorization', `Bearer ${employeeToken}`)
                .send(dto)
                .expect(201);

            const data = expectSuccessResponse<any>(response, 201);
            expect(data).toMatchObject({ name: 'Dresses', slug: 'dresses' });
            expect(data.id).toBeDefined();
            categoryIds.push(data.id);
        });

        it('should fail to create a category with a duplicate slug', async () => {
            const dto = {
                name: "Women's Clothing Duplicate",
                slug: 'womens-clothing',
            };
            const response = await request(app.getHttpServer())
                .post('/api/categories')
                .set('Authorization', `Bearer ${adminToken}`)
                .send(dto)
                .expect(409); // Conflict status for duplicate entries in Prisma

            expectErrorResponse(response, 409);
        });
    });

    describe('/categories (GET)', () => {
        it('should get a list of all categories', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/categories')
                .expect(200);

            logger.debug?.(
                `Response body: ${JSON.stringify(response.body, null, 2)}`,
                '/categories (GET)',
            );

            const data = expectSuccessResponse<any>(response, 200);
            expect(Array.isArray(data.categories)).toBe(true);
            expect(data.categories.length).toBeGreaterThanOrEqual(2);
            expect(
                data.categories.find((c: any) => c.slug === 'womens-clothing'),
            ).toBeDefined();
        });
    });

    describe('/categories/:id (GET)', () => {
        it('should get a single category by its ID', async () => {
            const womensCategory = await prisma.category.findFirst({
                where: { slug: 'womens-clothing' },
            });
            expect(womensCategory).not.toBeNull();
            const response = await request(app.getHttpServer())
                .get(`/api/categories/${womensCategory!.id}`)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.id).toBe(womensCategory!.id);
            expect(data.name).toBe("Women's Clothing");
        });

        it('should return 404 for a non-existent category ID', () => {
            return request(app.getHttpServer())
                .get('/api/categories/00000000-0000-0000-0000-000000000000')
                .expect(404)
                .expect((res) => {
                    expectErrorResponse(res, 404);
                });
        });
    });

    describe('/categories/slug/:slug (GET)', () => {
        it('should get a single category by its slug', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/categories/slug/dresses')
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.slug).toBe('dresses');
            expect(data.name).toBe('Dresses');
        });
    });

    describe('/categories/:id (PATCH)', () => {
        it('should update a category for an employee user', async () => {
            const dressesCategory = await prisma.category.findFirst({
                where: { slug: 'dresses' },
            });
            expect(dressesCategory).not.toBeNull();
            const dto = { name: 'Summer Dresses' };
            const response = await request(app.getHttpServer())
                .patch(`/api/categories/${dressesCategory!.id}`)
                .set('Authorization', `Bearer ${employeeToken}`)
                .send(dto)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.name).toBe('Summer Dresses');
            expect(data.slug).toBe('dresses'); // slug was not updated
        });

        it('should return 404 when trying to update a non-existent category', () => {
            return request(app.getHttpServer())
                .patch('/api/categories/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ name: 'New Name' })
                .expect(404)
                .expect((res) => {
                    expectErrorResponse(res, 404);
                });
        });
    });

    describe('/categories/:id (DELETE)', () => {
        it('should reject deletion for an employee user', async () => {
            const womensCategory = await prisma.category.findFirst({
                where: { slug: 'womens-clothing' },
            });
            expect(womensCategory).not.toBeNull();
            return request(app.getHttpServer())
                .delete(`/api/categories/admin/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${employeeToken}`)
                .expect(403) // Forbidden, as only admin can delete
                .expect((res) => {
                    expectErrorResponse(res, 403);
                });
        });

        it('shouldn not delete a parent category that has children', async () => {
            const womensCategory = await prisma.category.findFirst({
                where: { slug: 'womens-clothing' },
            });
            expect(womensCategory).not.toBeNull();
            await request(app.getHttpServer())
                .delete(`/api/categories/admin/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(409)
                .expect((res) => {
                    expectErrorResponse(res, 409);
                });
        });

        it('should delete a category for an admin user', async () => {
            const womensCategory = await prisma.category.findFirst({
                where: { slug: 'dresses' },
            });
            expect(womensCategory).not.toBeNull();
            await request(app.getHttpServer())
                .delete(`/api/categories/admin/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(204); // no content

            // Verify it's gone
            await request(app.getHttpServer())
                .get(`/api/categories/${womensCategory!.id}`)
                .expect(404);
        });

        it('should return 404 when trying to delete a non-existent category', () => {
            return request(app.getHttpServer())
                .delete(
                    '/api/categories/admin/00000000-0000-0000-0000-000000000000',
                )
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(404)
                .expect((res) => {
                    expectErrorResponse(res, 404);
                });
        });
    });
});
