import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import * as argon2 from 'argon2';
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

type AuthFixture = {
    adminToken: string;
    adminRoleId: string;
    customerRoleId: string;
};

describe('AuthModule (e2e)', () => {
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

    async function seedAuthFixture(): Promise<AuthFixture> {
        const permissions = await Promise.all(
            ['roles.read', 'roles.create', 'roles.update', 'roles.delete'].map(
                (name) => prisma.permission.create({ data: { name } }),
            ),
        );

        const [adminRole, customerRole] = await Promise.all([
            prisma.role.create({ data: { name: 'admin' } }),
            prisma.role.create({ data: { name: 'customer' } }),
        ]);

        await prisma.rolePermission.createMany({
            data: permissions.map((permission) => ({
                roleId: adminRole.id,
                permissionId: permission.id,
            })),
        });

        const admin = getUniqueTestData('auth-admin');
        await prisma.user.create({
            data: {
                email: admin.email,
                name: admin.name,
                passwordHash: await argon2.hash('password123'),
                roleId: adminRole.id,
            },
        });

        const loginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: admin.email, password: 'password123' })
            .expect(200);

        return {
            adminToken: extractAuthTokenFromResponse(loginResponse),
            adminRoleId: adminRole.id,
            customerRoleId: customerRole.id,
        };
    }

    function getRefreshCookie(response: request.Response): string {
        const cookies = response.headers['set-cookie'] as unknown as string[];
        expect(Array.isArray(cookies)).toBe(true);

        const refreshCookie = cookies.find((cookie) =>
            cookie.startsWith('refresh_token='),
        );
        expect(refreshCookie).toBeDefined();

        return refreshCookie!;
    }

    describe('POST /api/auth/register', () => {
        it('registers a customer, returns tokens, and sets the refresh cookie', async () => {
            const fixture = await seedAuthFixture();
            const unique = getUniqueTestData('auth-register');

            const response = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                    phone: '01012345678',
                })
                .expect(201);

            const data = expectSuccessResponse<any>(response, 201);
            expect(data.accessToken).toEqual(expect.any(String));
            expect(data.refreshToken).toEqual(expect.any(String));
            expect(data.user).toMatchObject({
                email: unique.email,
                name: unique.name,
                phone: '01012345678',
            });

            const refreshCookie = getRefreshCookie(response);
            expect(refreshCookie).toContain('HttpOnly');
            expect(refreshCookie).toContain('Path=/api/auth');
            expect(refreshCookie).toContain('SameSite=Strict');

            const savedUser = await prisma.user.findUnique({
                where: { email: unique.email },
            });
            expect(savedUser?.roleId).toBe(fixture.customerRoleId);
        });

        it('rejects duplicate email and invalid payloads', async () => {
            await seedAuthFixture();
            const unique = getUniqueTestData('auth-duplicate');

            await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                })
                .expect(201);

            const duplicateResponse = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                })
                .expect(409);
            expectErrorResponse(duplicateResponse, 409);

            const invalidResponse = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({ email: 'bad-email', name: 'A', password: '123' })
                .expect(400);
            expectErrorResponse(invalidResponse, 400);
        });

        it('fails clearly when the required customer role is missing', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: getUniqueTestData('auth-no-role').email,
                    name: 'No Customer Role',
                    password: 'password123',
                })
                .expect(404);

            const error = expectErrorResponse(response, 404);
            expect(error.code).toBe('ROLE_NOT_FOUND');
        });
    });

    describe('POST /api/auth/login', () => {
        it('logs in with valid credentials and rejects invalid credentials', async () => {
            await seedAuthFixture();
            const unique = getUniqueTestData('auth-login');

            await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                })
                .expect(201);

            const response = await request(app.getHttpServer())
                .post('/api/auth/login')
                .send({ email: unique.email, password: 'password123' })
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.accessToken).toEqual(expect.any(String));
            expect(data.refreshToken).toEqual(expect.any(String));
            expect(data.user.email).toBe(unique.email);
            expect(getRefreshCookie(response)).toContain('Path=/api/auth');

            const invalidPassword = await request(app.getHttpServer())
                .post('/api/auth/login')
                .send({ email: unique.email, password: 'wrong-password' })
                .expect(401);
            expectErrorResponse(invalidPassword, 401);

            const unknownUser = await request(app.getHttpServer())
                .post('/api/auth/login')
                .send({
                    email: getUniqueTestData('missing').email,
                    password: 'password123',
                })
                .expect(404);
            expectErrorResponse(unknownUser, 404);
        });

        it('rejects invalid login payloads', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/auth/login')
                .send({ email: 'bad-email', password: '' })
                .expect(400);

            expectErrorResponse(response, 400);
        });
    });

    describe('POST /api/auth/refresh-token', () => {
        it('rotates refresh tokens and rejects old token reuse', async () => {
            await seedAuthFixture();
            const unique = getUniqueTestData('auth-refresh');

            const registerResponse = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                })
                .expect(201);

            const originalCookie = getRefreshCookie(registerResponse);

            const refreshResponse = await request(app.getHttpServer())
                .post('/api/auth/refresh-token')
                .set('Cookie', originalCookie)
                .expect(200);

            const refreshData = expectSuccessResponse<any>(
                refreshResponse,
                200,
            );
            expect(refreshData.accessToken).toEqual(expect.any(String));

            const rotatedCookie = getRefreshCookie(refreshResponse);
            expect(rotatedCookie).not.toBe(originalCookie);

            const reuseResponse = await request(app.getHttpServer())
                .post('/api/auth/refresh-token')
                .set('Cookie', originalCookie)
                .expect(401);
            expectErrorResponse(reuseResponse, 401);
        });

        it('rejects missing and invalid refresh cookies', async () => {
            const missingResponse = await request(app.getHttpServer())
                .post('/api/auth/refresh-token')
                .expect(401);
            expectErrorResponse(missingResponse, 401);

            const invalidResponse = await request(app.getHttpServer())
                .post('/api/auth/refresh-token')
                .set('Cookie', 'refresh_token=not-a-real-token')
                .expect(401);
            expectErrorResponse(invalidResponse, 401);
        });
    });

    describe('POST /api/auth/logout', () => {
        it('clears the refresh cookie for authenticated users', async () => {
            await seedAuthFixture();
            const unique = getUniqueTestData('auth-logout');

            const registerResponse = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: unique.email,
                    name: unique.name,
                    password: 'password123',
                })
                .expect(201);

            const token = extractAuthTokenFromResponse(registerResponse);

            const response = await request(app.getHttpServer())
                .post('/api/auth/logout')
                .set('Authorization', `Bearer ${token}`)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.message).toBe('Logged out successfully');
            expect(getRefreshCookie(response)).toMatch(
                /Max-Age=0|Expires=Thu, 01 Jan 1970/,
            );
        });

        it('rejects unauthenticated logout', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/auth/logout')
                .expect(401);

            expectErrorResponse(response, 401);
        });
    });

    describe('/api/auth/roles', () => {
        it('enforces authentication and permissions', async () => {
            const fixture = await seedAuthFixture();

            const unauthenticated = await request(app.getHttpServer())
                .get('/api/auth/roles')
                .expect(401);
            expectErrorResponse(unauthenticated, 401);

            const customer = getUniqueTestData('auth-customer');
            const customerRegister = await request(app.getHttpServer())
                .post('/api/auth/register')
                .send({
                    email: customer.email,
                    name: customer.name,
                    password: 'password123',
                })
                .expect(201);
            const customerToken =
                extractAuthTokenFromResponse(customerRegister);

            const forbidden = await request(app.getHttpServer())
                .get('/api/auth/roles')
                .set('Authorization', `Bearer ${customerToken}`)
                .expect(403);
            expectErrorResponse(forbidden, 403);

            const allowed = await request(app.getHttpServer())
                .get('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .expect(200);
            expectSuccessResponse<any[]>(allowed, 200);
        });

        it('creates, updates, lists, and deletes editable roles', async () => {
            const fixture = await seedAuthFixture();

            const createResponse = await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({
                    name: 'Support',
                    permissions: ['roles.read'],
                })
                .expect(201);

            const created = expectSuccessResponse<any>(createResponse, 201);
            expect(created.name).toBe('support');
            expect(created.permissions).toEqual(['roles.read']);

            const listResponse = await request(app.getHttpServer())
                .get('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .expect(200);

            const roles = expectSuccessResponse<any[]>(listResponse, 200);
            expect(roles.some((role) => role.name === 'support')).toBe(true);
            expect(roles.some((role) => role.name === 'admin')).toBe(false);
            expect(roles.some((role) => role.name === 'customer')).toBe(false);

            const updateResponse = await request(app.getHttpServer())
                .patch(`/api/auth/roles/${created.id}/permissions`)
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ permissions: ['roles.read', 'roles.update'] })
                .expect(200);

            const updated = expectSuccessResponse<any>(updateResponse, 200);
            expect(updated.permissions).toEqual(['roles.read', 'roles.update']);

            await request(app.getHttpServer())
                .delete(`/api/auth/roles/${created.id}`)
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .expect(204);

            await expect(
                prisma.role.findUnique({ where: { id: created.id } }),
            ).resolves.toBeNull();
        });

        it('rejects duplicate, protected, invalid, and missing role operations', async () => {
            const fixture = await seedAuthFixture();

            await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ name: 'support', permissions: [] })
                .expect(201);

            const duplicate = await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ name: 'support', permissions: [] })
                .expect(409);
            expectErrorResponse(duplicate, 409);

            const protectedRole = await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ name: 'customer', permissions: [] })
                .expect(403);
            expectErrorResponse(protectedRole, 403);

            const invalidPayload = await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ name: 'bad-role', permissions: 'roles.read' })
                .expect(400);
            expectErrorResponse(invalidPayload, 400);

            const missingPermission = await request(app.getHttpServer())
                .post('/api/auth/roles')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ name: 'auditor', permissions: ['missing.permission'] })
                .expect(404);
            expectErrorResponse(missingPermission, 404);

            const protectedUpdate = await request(app.getHttpServer())
                .patch(`/api/auth/roles/${fixture.adminRoleId}/permissions`)
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .send({ permissions: ['roles.read'] })
                .expect(403);
            expectErrorResponse(protectedUpdate, 403);

            const missingDelete = await request(app.getHttpServer())
                .delete('/api/auth/roles/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${fixture.adminToken}`)
                .expect(404);
            expectErrorResponse(missingDelete, 404);
        });
    });
});
