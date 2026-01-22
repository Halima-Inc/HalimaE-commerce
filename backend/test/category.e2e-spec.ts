import { INestApplication, LoggerService } from '@nestjs/common';
import request from 'supertest';
import { PrismaService } from '../src/prisma/prisma.service';
import { CreateUserDto } from '../src/users/dto';
import { UsersService } from '../src/users/users.service';
import { setupE2ETest, teardownE2ETest } from './jest-e2e.setup';
import { LogService } from '../src/logger/log.service';
import { 
    expectSuccessResponse, 
    expectErrorResponse, 
    extractAuthTokenFromResponse
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

        // 1. Create Roles
        const adminRole = await prisma.role.create({ data: { name: 'admin' } });
        const employeeRole = await prisma.role.create({ data: { name: 'employee' } });
        adminRoleId = adminRole.id;
        employeeRoleId = employeeRole.id;

        // 2. Create Admin user directly to get the first token
        const adminDto: CreateUserDto = { name: 'Test Admin', email: 'admin-cat@test.com', password: 'password123', roleId: adminRoleId };
        // In a real scenario, the first admin is often seeded into the DB.
        // We simulate this by calling the user service directly.
        // We can't use the signup endpoint as it requires an admin token.
        const usersService = app.get(UsersService);
        const adminUser = await usersService.create(adminDto);
        
        // 3. Log in as the seeded admin to get a token
        const adminLoginRes = await request(app.getHttpServer())
            .post('/api/admin/auth/login')
            .send({ email: adminDto.email, password: adminDto.password });
        adminToken = extractAuthTokenFromResponse(adminLoginRes);

        // 4. Use the admin token to create an employee user via the signup endpoint
        const employeeDto: CreateUserDto = { name: 'Test Employee', email: 'employee-cat@test.com', password: 'password123', roleId: employeeRoleId };
        await request(app.getHttpServer())
            .post('/api/admin/auth/signup')
            .send(employeeDto)
            .set('Authorization', `Bearer ${adminToken}`);

        // Retrieve the created employee to get their ID for cleanup
        const employeeUser = await prisma.user.findUnique({ where: { email: employeeDto.email } });
        expect(employeeUser).not.toBeNull();

        // 5. Log in as the new employee to get their token
        const employeeLoginRes = await request(app.getHttpServer())
            .post('/api/admin/auth/login')
            .send({ email: employeeDto.email, password: employeeDto.password });
        employeeToken = extractAuthTokenFromResponse(employeeLoginRes);
    }, 30000); // Set timeout to 30 seconds for setup

    afterAll(async () => {
        await teardownE2ETest(app, prisma);
    });

    describe('/categories (POST)', () => {
        it('should reject creation for unauthenticated user', () => {
        return request(app.getHttpServer())
            .post('/api/categories')
            .send({ name: "Women's Clothing", slug: 'womens-clothing' })
            .expect(401)
            .expect(res => {
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
            const dto = { name: 'Dresses', slug: 'dresses', parentId: parentCategory!.id };
            
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
    });

    describe('/categories (GET)', () => {
        it('should get a list of all categories', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/categories')
                .expect(200);

            logger.debug?.(`Response body: ${JSON.stringify(response.body, null, 2)}`, '/categories (GET)');

            const data = expectSuccessResponse<any>(response, 200);
            expect(Array.isArray(data.categories)).toBe(true);
            expect(data.categories.length).toBeGreaterThanOrEqual(2);
            expect(data.categories.find((c: any) => c.slug === 'womens-clothing')).toBeDefined();
        });
    });

    describe('/categories/:id (GET)', () => {
        it('should get a single category by its ID', async () => {
            const womensCategory = await prisma.category.findFirst({ where: { slug: 'womens-clothing' } });
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
                .expect(res => {
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
            const dressesCategory = await prisma.category.findFirst({ where: { slug: 'dresses' } });
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
    });

    describe('/categories/:id (DELETE)', () => {
        it('should reject deletion for an employee user', async () => {
            const womensCategory = await prisma.category.findFirst({ where: { slug: 'womens-clothing' } });
            expect(womensCategory).not.toBeNull();
            return request(app.getHttpServer())
                .delete(`/api/categories/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${employeeToken}`)
                .expect(403) // Forbidden, as only admin can delete
                .expect(res => {
                    expectErrorResponse(res, 403);
                });
        });
        
        it('shouldn not delete a parent category that has children', async () => {
            const womensCategory = await prisma.category.findFirst({ where: { slug: 'womens-clothing' } });
            expect(womensCategory).not.toBeNull();
            await request(app.getHttpServer())
                .delete(`/api/categories/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(400)
                .expect(res => {
                    expectErrorResponse(res, 400);
                });
        });
        
        it('should delete a category for an admin user', async () =>{
            const womensCategory = await prisma.category.findFirst({ where: { slug: 'dresses' } });
            expect(womensCategory).not.toBeNull();
            await request(app.getHttpServer())
                .delete(`/api/categories/${womensCategory!.id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(204); // no content

            // Verify it's gone
            await request(app.getHttpServer())
                .get(`/api/categories/${womensCategory!.id}`)
                .expect(404);
        });

        it('should return 404 when trying to delete a non-existent category', () => {
            return request(app.getHttpServer())
                .delete('/api/categories/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(404)
                .expect(res => {
                    expectErrorResponse(res, 404);
                });
        });
    });
});