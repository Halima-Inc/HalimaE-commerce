import { INestApplication, LoggerService } from '@nestjs/common';
import request from 'supertest';
import { setupE2ETest, teardownE2ETest, getUniqueTestData } from './jest-e2e.setup';
import * as argon2 from 'argon2';
import { PrismaService } from '../src/prisma/prisma.service';
import { CreateAddressDto } from '../src/customer/dto';
import { LogService } from '../src/logger/log.service';
import { extractAuthTokenFromResponse, expectSuccessResponse, expectErrorResponse } from './test-utils';

describe('CustomerController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let adminToken: string;
    let customerToken: string;
    let customerRefreshCookie: string;
    let addressId: string;
    let logger: LoggerService;
    let testCustomer: { email: string; name: string; slug: string; sku: string };

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());
        logger = app.get<LoggerService>(LogService);
        testCustomer = getUniqueTestData('customer');

        // 1. Create Roles
        let role = await prisma.role.findFirst({
            where: { name: 'admin' },
            select: { id: true }
        });
        if (!role) {
            role = await prisma.role.create({ data: { name: 'admin' }, select: { id: true } });
        }

        const admin = await prisma.user.upsert({
            where: { email: 'customeradmin@test.com' },
            update: {},
            create: {
                name: 'CustomerAdmin test',
                email: 'customeradmin@test.com',
                passwordHash: await argon2.hash('password'),
                roleId: role.id,
            },
            select: {
                id: true,
                email: true,
                passwordHash: true
            }
        });

        adminToken = extractAuthTokenFromResponse(await request(app.getHttpServer())
            .post('/api/admin/auth/login')
            .send({ email: admin.email, password: 'password' }));

        expect(adminToken).toBeDefined();
    }, 60000);

    afterAll(async () => {
        await teardownE2ETest(app, prisma);
    }, 60000);


    describe('POST /customers/auth', () => {
        it('should create a new customer and set refresh_token cookie', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/signup')
                .send({
                    name: testCustomer.name,
                    email: testCustomer.email,
                    password: 'password',
                    phone: '1234567890'
                });
            logger.debug?.(`Response: ${JSON.stringify(response.body)}`, 'CustomerAuthController');

            const data = expectSuccessResponse<any>(response, 201);
            expect(data.name).toBe(testCustomer.name);
            expect(data.email).toBe(testCustomer.email);
            expect(data.phone).toBe('1234567890');
            expect(data).toHaveProperty('access_token');
            expect(data.refresh_token).toBeUndefined(); // Should NOT be in body
            customerToken = data.access_token;

            // Verify refresh_token cookie is set
            const cookies = response.headers['set-cookie'] as unknown as string[];
            expect(cookies).toBeDefined();
            const refreshCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));
            expect(refreshCookie).toBeDefined();
            expect(refreshCookie).toContain('HttpOnly');
            customerRefreshCookie = refreshCookie!;
        });

        it('should reject signup with duplicate email', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/signup')
                .send({
                    name: testCustomer.name,
                    email: testCustomer.email,
                    password: 'password',
                    phone: '1234567890'
                });

            expectErrorResponse(response, 409);
        });

        it('should login a customer and set refresh_token cookie', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'password' });

            const data = expectSuccessResponse<any>(response, 200);
            expect(data).toHaveProperty('access_token');
            expect(data.refresh_token).toBeUndefined(); // Should NOT be in body
            customerToken = data.access_token;

            // Verify refresh_token cookie is set
            const cookies = response.headers['set-cookie'] as unknown as string[];
            expect(cookies).toBeDefined();
            const refreshCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));
            expect(refreshCookie).toBeDefined();
            expect(refreshCookie).toContain('HttpOnly');
            customerRefreshCookie = refreshCookie!;
        });

        it('should reject login with invalid password', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'wrongpassword' });

            expectErrorResponse(response, 401);
        });

        it('should reject login with non-existent email', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: 'nonexistent@test.com', password: 'password' });

            expectErrorResponse(response, 401);
        });
    });

    describe('POST /customers/auth/refresh-token', () => {
        it('should refresh access token using cookie', async () => {
            // First login to get a fresh cookie
            const loginResp = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'password' });

            const loginCookies = loginResp.headers['set-cookie'] as unknown as string[];
            const loginCookie = loginCookies.find((c: string) => c.startsWith('refresh_token='))!;
            const oldToken = extractAuthTokenFromResponse(loginResp);

            // Small delay to ensure different iat timestamp in JWT
            await new Promise(resolve => setTimeout(resolve, 1100));

            // Use the cookie to refresh
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', loginCookie);

            expect(response.status).toBe(201);
            const data = expectSuccessResponse<any>(response, 201);
            expect(data.access_token).toBeDefined();
            expect(data.access_token).not.toBe(oldToken); // Should be a new token (different iat)

            // Verify new refresh_token cookie is set (token rotation)
            const cookies = response.headers['set-cookie'] as unknown as string[];
            expect(cookies).toBeDefined();
            const newRefreshCookie = cookies.find((c: string) => c.startsWith('refresh_token='))!;
            expect(newRefreshCookie).toBeDefined();
            expect(newRefreshCookie).not.toBe(loginCookie); // Should be rotated

            // Update for subsequent tests
            customerRefreshCookie = newRefreshCookie;
            customerToken = data.access_token;
        });

        it('should reject refresh without cookie', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token');

            expectErrorResponse(response, 401);
            expect(response.body.error.message).toContain('Refresh token not found');
        });

        it('should reject refresh with invalid token', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', 'refresh_token=invalid_token');

            expectErrorResponse(response, 401);
        });

        it('should prevent token reuse (token rotation)', async () => {
            // Get a fresh token
            const loginResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'password' });

            const loginCookies = loginResponse.headers['set-cookie'] as unknown as string[];
            const originalRefreshCookie = loginCookies.find((c: string) => c.startsWith('refresh_token='))!;

            // Use the token once
            await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', originalRefreshCookie)
                .expect(201);

            // Try to reuse the old token - should fail
            const reuseResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', originalRefreshCookie);

            expectErrorResponse(reuseResponse, 401);
        });
    });

    describe('POST /customers/auth/logout', () => {
        it('should logout from current device and clear cookie', async () => {
            // Login to get a fresh session
            const loginResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'password' });

            const loginCookies = loginResponse.headers['set-cookie'] as unknown as string[];
            const logoutRefreshCookie = loginCookies.find((c: string) => c.startsWith('refresh_token='))!;
            const logoutToken = extractAuthTokenFromResponse(loginResponse);

            // Logout
            const logoutResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/logout')
                .set('Authorization', `Bearer ${logoutToken}`)
                .set('Cookie', logoutRefreshCookie);

            expectSuccessResponse(logoutResponse, 200);
            expect(logoutResponse.body.data.message).toContain('Logged out');

            // Verify cookie is cleared
            const logoutCookies = logoutResponse.headers['set-cookie'] as unknown as string[];
            expect(logoutCookies).toBeDefined();
            const clearedCookie = logoutCookies.find((c: string) => c.startsWith('refresh_token='))!;
            expect(clearedCookie).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/);

            // Try to use the token - should fail
            const refreshResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', logoutRefreshCookie);

            expectErrorResponse(refreshResponse, 401);
        });

        it('should reject logout without authentication', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/logout');

            expectErrorResponse(response, 401);
        });
    });

    describe('POST /customers/auth/logout-all', () => {
        it('should logout from all devices', async () => {
            // Create multiple sessions by logging in multiple times
            const login1 = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .set('User-Agent', 'Device1')
                .send({ email: testCustomer.email, password: 'password' });

            const login2 = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .set('User-Agent', 'Device2')
                .send({ email: testCustomer.email, password: 'password' });

            const token1 = extractAuthTokenFromResponse(login1);
            const cookie1 = (login1.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;
            const cookie2 = (login2.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;

            // Logout from all devices
            const logoutAllResponse = await request(app.getHttpServer())
                .post('/api/customers/auth/logout-all')
                .set('Authorization', `Bearer ${token1}`)
                .set('Cookie', cookie1);

            expectSuccessResponse(logoutAllResponse, 200);
            expect(logoutAllResponse.body.data.message).toContain('Logged out');

            // Verify both tokens are revoked
            await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', cookie1)
                .expect(401);

            await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', cookie2)
                .expect(401);
        });

        it('should reject unauthenticated logout-all request', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/customers/auth/logout-all')
                .set('Cookie', ''); // Explicitly clear any cookies

            expectErrorResponse(response, 401);
        });
    });

    describe('Multi-device session management', () => {
        it('should maintain separate sessions per device', async () => {
            // Get customer for cleanup
            const customer = await prisma.customer.findUnique({ where: { email: testCustomer.email } });
            if (customer) {
                await prisma.customerRefreshToken.deleteMany({ where: { customerId: customer.id } });
            }

            // Login from two devices
            const device1Login = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .set('User-Agent', 'Chrome/Windows')
                .send({ email: testCustomer.email, password: 'password' });

            const device2Login = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .set('User-Agent', 'Safari/Mac')
                .send({ email: testCustomer.email, password: 'password' });

            const token1 = extractAuthTokenFromResponse(device1Login);
            const cookie1 = (device1Login.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;
            const cookie2 = (device2Login.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;

            expect(cookie1).toBeDefined();
            expect(cookie2).toBeDefined();

            // Both should be able to refresh independently
            const refresh1 = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', cookie1)
                .expect(201);

            const refresh2 = await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', cookie2)
                .expect(201);

            // Get updated cookies after refresh
            const newCookie1 = (refresh1.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;
            const newCookie2 = (refresh2.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;

            // Verify tokens are different
            expect(newCookie1).not.toBe(newCookie2);

            // Verify we have exactly 2 active tokens in database
            const tokens = await prisma.customerRefreshToken.findMany({
                where: { customerId: customer!.id, isRevoked: false }
            });
            expect(tokens).toHaveLength(2);

            // Logout from device1 only
            await request(app.getHttpServer())
                .post('/api/customers/auth/logout')
                .set('Authorization', `Bearer ${token1}`)
                .set('Cookie', newCookie1)
                .expect(200);

            // Verify only 1 token left
            const tokensAfterLogout = await prisma.customerRefreshToken.findMany({
                where: { customerId: customer!.id, isRevoked: false }
            });
            expect(tokensAfterLogout).toHaveLength(1);

            // Device1 should be logged out
            await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', newCookie1)
                .expect(401);

            // Device2 should still work
            await request(app.getHttpServer())
                .post('/api/customers/auth/refresh-token')
                .set('Cookie', newCookie2)
                .expect(201);

            // Update customerToken for subsequent tests
            const finalLogin = await request(app.getHttpServer())
                .post('/api/customers/auth/login')
                .send({ email: testCustomer.email, password: 'password' });
            customerToken = extractAuthTokenFromResponse(finalLogin);
            customerRefreshCookie = (finalLogin.headers['set-cookie'] as unknown as string[]).find((c: string) => c.startsWith('refresh_token='))!;
        });
    });

    describe('GET /customers/me', () => {
        it('should get the current customer', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/me')
                .set('Authorization', `Bearer ${customerToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data).toHaveProperty('id');
            expect(data.name).toContain('customer'); // Name contains the prefix
            expect(data.email).toBe(testCustomer.email);
            expect(data.phone).toBe('1234567890');
        });
    });

    describe('PATCH /customers/me', () => {
        it('should update the current customer', async () => {
            const response = await request(app.getHttpServer())
                .patch('/api/customers/me')
                .set('Authorization', `Bearer ${customerToken}`)    
                .send({ name: `${testCustomer.name} updated` });
                
            const data = expectSuccessResponse<any>(response, 200);
            expect(data.name).toBe(`${testCustomer.name} updated`);
        });
    });

    describe('GET /customers', () => {
        it('should get all customers for admin', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all')
                .set('Authorization', `Bearer ${adminToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);
        });

        it('should not get all customers for customer', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all')
                .set('Authorization', `Bearer ${customerToken}`);
                
            expectErrorResponse(response, 401); // or 403 depending on guard implementation, JwtUserGuard will fail validation -> 401
        });

        it('should get all customers with pagination', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?page=1&limit=10')
                .set('Authorization', `Bearer ${adminToken}`);
                
            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);
            expect(data.meta.total).toBeGreaterThan(0);
            expect(data.meta.totalPages).toBeGreaterThan(0);
        });

        it('should get all customers with search', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?search=customer')
                .set('Authorization', `Bearer ${adminToken}`);
                
            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);
            expect(data.data.length).toBeGreaterThan(0);
            expect(data.data[0].name).toContain('customer');
        });

        it('should get all customers with sort', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?sort=name&order=desc')
                .set('Authorization', `Bearer ${adminToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);
            
            const sortedNames = data.data.map((customer: any) => customer.name);
            
            for (let i = 0; i < sortedNames.length - 1; i++) {
                expect(sortedNames[i]).toBeGreaterThanOrEqual(sortedNames[i + 1]);
            }
        });

        it('should get customers sorted by totalSpent (most paying customers)', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?sort=totalSpent&order=desc')
                .set('Authorization', `Bearer ${adminToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);

            // Verify response includes totalSpent field
            if (data.data.length > 0) {
                expect(data.data[0]).toHaveProperty('totalSpent');
                expect(typeof data.data[0].totalSpent).toBe('number');
            }

            // Verify descending order by totalSpent
            for (let i = 0; i < data.data.length - 1; i++) {
                expect(data.data[i].totalSpent).toBeGreaterThanOrEqual(data.data[i + 1].totalSpent);
            }
        });

        it('should get customers sorted by orderCount (most frequent buyers)', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?sort=orderCount&order=desc')
                .set('Authorization', `Bearer ${adminToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);

            // Verify response includes orderCount field
            if (data.data.length > 0) {
                expect(data.data[0]).toHaveProperty('orderCount');
                expect(typeof data.data[0].orderCount).toBe('number');
            }

            // Verify descending order by orderCount
            for (let i = 0; i < data.data.length - 1; i++) {
                expect(data.data[i].orderCount).toBeGreaterThanOrEqual(data.data[i + 1].orderCount);
            }
        });

        it('should get customers sorted by totalSpent in ascending order', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/admin/all?sort=totalSpent&order=asc')
                .set('Authorization', `Bearer ${adminToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.data).toBeInstanceOf(Array);

            // Verify ascending order by totalSpent
            for (let i = 0; i < data.data.length - 1; i++) {
                expect(data.data[i].totalSpent).toBeLessThanOrEqual(data.data[i + 1].totalSpent);
            }
        });
    });

    describe('POST /customers/addresses', () => {
        it('should create a new address for the current customer', async () => {
            const address: CreateAddressDto = {
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '123 Main St',
                line2: 'Apt 4B',
                city: 'New York',
                postalCode: '10001',
                country: 'USA',
                isDefault: true,
            }
            const response = await request(app.getHttpServer())
                .post('/api/customers/addresses')
                .set('Authorization', `Bearer ${customerToken}`)
                .send(address);
            
            const data = expectSuccessResponse<any>(response, 201);
            expect(data).toHaveProperty('id');
            expect(data.firstName).toBe(address.firstName);
            expect(data.lastName).toBe(address.lastName);
            expect(data.phone).toBe(address.phone);
            expect(data.line1).toBe(address.line1);
            expect(data.line2).toBe(address.line2);
            expect(data.city).toBe(address.city); 
            expect(data.postalCode).toBe(address.postalCode);
            expect(data.country).toBe(address.country);
            expect(data.isDefault).toBe(address.isDefault);

            addressId = data.id;
        });
        
        it('should return 400 if required fields are missing', async () => {
            const address = {
                firstName: 'John',
                // missing lastName  
                phone: '1234567890',
                line1: '123 Main St',
                line2: 'Apt 4B',
                city: 'New York',
                country: 'USA',
                isDefault: true,
            }

            const response = await request(app.getHttpServer())
                .post('/api/customers/addresses')
                .set('Authorization', `Bearer ${customerToken}`)
                .send(address);

            expectErrorResponse(response, 400);
        });

        it('should return 400 if postal code is invalid', async () => {
            const address: CreateAddressDto = {
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '123 Main St',
                line2: 'Apt 4B',
                city: 'New York',
                country: 'USA',
                postalCode: '1234567890', // Invalid postal code
                isDefault: true,
            }

            const response = await request(app.getHttpServer())
                .post('/api/customers/addresses')
                .set('Authorization', `Bearer ${customerToken}`)
                .send(address);
            expectErrorResponse(response, 400);
        });
    });

    describe('GET /customers/addresses/:id', () => {
        it('should get an address for the current customer', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/customers/addresses/${addressId}`)
                .set('Authorization', `Bearer ${customerToken}`);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data).toHaveProperty('id');
            expect(data.firstName).toBe('John');
            expect(data.lastName).toBe('Doe');            
        });

        it('should return 404 if address not found', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/addresses/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 404);
        });


        it('should return 401 if not authenticated', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/customers/addresses/${addressId}`);
            expectErrorResponse(response, 401);
        });
    });

    describe('GET /customers/addresses', () => {
        it('should get all addresses for the current customer', async () => {
            const response = await request(app.getHttpServer())
               .get('/api/customers/addresses')
               .set('Authorization', `Bearer ${customerToken}`);
               
            const data = expectSuccessResponse<any>(response, 200);
            expect(data).toHaveLength(1);
        });

        it('should return 401 if not authenticated' , async () => {
            const response = await request(app.getHttpServer())
                .get('/api/customers/addresses');

            expectErrorResponse(response, 401);
        });
    });
});