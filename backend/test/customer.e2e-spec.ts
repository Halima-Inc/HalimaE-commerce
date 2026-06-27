import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import * as argon2 from 'argon2';
import { randomUUID } from 'crypto';
import { PrismaService } from '../src/prisma/prisma.service';
import {
    getUniqueTestData,
    resetE2EDatabase,
    setupE2ETest,
    teardownE2ETest,
} from './jest-e2e.setup';
import {
    expectErrorResponse,
    expectSuccessResponse,
    extractAuthTokenFromResponse,
} from './test-utils';

jest.setTimeout(30000);

describe('UsersModule / CustomersController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());
    }, 30000);

    afterAll(async () => {
        if (app && prisma) {
            await teardownE2ETest(app, prisma);
        }
    }, 60000);

    beforeEach(async () => {
        await resetE2EDatabase(app);
    });

    // TODO: Refactor to be common test utility for seeding roles and creating users with tokens
    async function seedRoles() {
        const roles = await Promise.all([
            prisma.role.create({ data: { name: 'admin' } }),
            prisma.role.create({ data: { name: 'customer' } }),
        ]);

        return {
            adminRoleId: roles[0].id,
            customerRoleId: roles[1].id,
        };
    } /////////////////////////////////////////////////////////

    // TODO: Refactor to be common test utility for creating users and getting tokens
    async function createUser(roleId: string, prefix: string) {
        const unique = getUniqueTestData(prefix);
        await prisma.user.create({
            data: {
                email: unique.email,
                name: unique.name,
                phone: '01012345678',
                passwordHash: await argon2.hash('password123'),
                roleId,
            },
        });

        const response = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: unique.email, password: 'password123' })
            .expect(200);

        return {
            ...unique,
            token: extractAuthTokenFromResponse(response),
        };
    } /////////////////////////////////////////////////////////

    function validAddress(overrides: Record<string, unknown> = {}) {
        return {
            firstName: 'John',
            lastName: 'Doe',
            phone: '01012345678',
            line1: '123 Main Street',
            line2: 'Apt 2',
            city: 'New York',
            country: 'United States',
            postalCode: '10001',
            isDefault: true,
            ...overrides,
        };
    }

    describe('profile endpoints', () => {
        it('returns and updates the authenticated customer profile', async () => {
            const { customerRoleId } = await seedRoles();
            const customer = await createUser(customerRoleId, 'customer');

            const getResponse = await request(app.getHttpServer())
                .get('/api/customers/me')
                .set('Authorization', `Bearer ${customer.token}`)
                .expect(200);

            const profile = expectSuccessResponse<any>(getResponse, 200);
            expect(profile).toMatchObject({
                email: customer.email,
                name: customer.name,
                phone: '01012345678',
            });

            const updateResponse = await request(app.getHttpServer())
                .patch('/api/customers/me')
                .set('Authorization', `Bearer ${customer.token}`)
                .send({
                    name: 'Updated Customer',
                    phone: '01112345678',
                })
                .expect(200);

            const updated = expectSuccessResponse<any>(updateResponse, 200);
            expect(updated).toMatchObject({
                email: customer.email,
                name: 'Updated Customer',
                phone: '01112345678',
            });
        });

        it('rejects unauthenticated and invalid profile requests', async () => {
            const { customerRoleId } = await seedRoles();
            const customer = await createUser(customerRoleId, 'customer');

            const unauthenticated = await request(app.getHttpServer())
                .get('/api/customers/me')
                .expect(401);
            expectErrorResponse(unauthenticated, 401);

            const invalid = await request(app.getHttpServer())
                .patch('/api/customers/me')
                .set('Authorization', `Bearer ${customer.token}`)
                .send({ email: 'not-an-email', phone: '1' })
                .expect(400);
            expectErrorResponse(invalid, 400);
        });
    });

    describe('admin customer listing', () => {
        it('lists only customers for admin users with pagination and search', async () => {
            const { adminRoleId, customerRoleId } = await seedRoles();
            const admin = await createUser(adminRoleId, 'admin');
            const customer = await createUser(customerRoleId, 'customer-list');

            const response = await request(app.getHttpServer())
                .get(
                    `/api/customers/admin/all?search=${customer.email}&page=1&limit=5`,
                )
                .set('Authorization', `Bearer ${admin.token}`)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toHaveLength(1);
            expect(data.data[0].email).toBe(customer.email);
            expect(data.meta.total).toBe(1);
            expect(data.meta.totalPages).toBe(1);
        });

        it('forbids ordinary customers from admin customer listing', async () => {
            const { customerRoleId } = await seedRoles();
            const customer = await createUser(customerRoleId, 'customer');

            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all')
                .set('Authorization', `Bearer ${customer.token}`)
                .expect(403);

            expectErrorResponse(response, 403);
        });
    });

    describe('address endpoints', () => {
        it('creates, lists, reads, and updates customer addresses', async () => {
            const { customerRoleId } = await seedRoles();
            const customer = await createUser(
                customerRoleId,
                'customer-address',
            );

            const address = validAddress();
            const createResponse = await request(app.getHttpServer())
                .post('/api/customers/addresses')
                .set('Authorization', `Bearer ${customer.token}`)
                .send(address);

            const created = expectSuccessResponse<any>(createResponse, 201);
            expect(created).toMatchObject(address);

            const listResponse = await request(app.getHttpServer())
                .get('/api/customers/addresses')
                .set('Authorization', `Bearer ${customer.token}`)
                .expect(200);

            const addresses = expectSuccessResponse<any[]>(listResponse, 200);
            expect(addresses).toHaveLength(1);
            expect(addresses[0].id).toBe(created.id);

            const getResponse = await request(app.getHttpServer())
                .get(`/api/customers/addresses/${created.id}`)
                .set('Authorization', `Bearer ${customer.token}`)
                .expect(200);

            const found = expectSuccessResponse<any>(getResponse, 200);
            expect(found.id).toBe(created.id);

            const updateResponse = await request(app.getHttpServer())
                .patch(`/api/customers/addresses/${created.id}`)
                .set('Authorization', `Bearer ${customer.token}`)
                .send({ city: 'Alexandria', isDefault: false })
                .expect(200);

            const updated = expectSuccessResponse<any>(updateResponse, 200);
            expect(updated).toMatchObject({
                id: created.id,
                city: 'Alexandria',
                isDefault: false,
            });
        });

        it('rejects invalid, missing, and unauthenticated address access', async () => {
            const { customerRoleId } = await seedRoles();
            const customer = await createUser(
                customerRoleId,
                'customer-address',
            );

            const invalidCreate = await request(app.getHttpServer())
                .post('/api/customers/addresses')
                .set('Authorization', `Bearer ${customer.token}`)
                .send(validAddress({ postalCode: 'not a postal code' }))
                .expect(400);

            expectErrorResponse(invalidCreate, 400);

            const missing = await request(app.getHttpServer())
                .get(`/api/customers/addresses/${randomUUID()}`)
                .set('Authorization', `Bearer ${customer.token}`)
                .expect(404);

            expectErrorResponse(missing, 404);

            const unauthenticated = await request(app.getHttpServer())
                .get('/api/customers/addresses')
                .expect(401);

            expectErrorResponse(unauthenticated, 401);
        });
    });
});
