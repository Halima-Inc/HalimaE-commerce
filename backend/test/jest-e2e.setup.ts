import 'dotenv/config';
import { Test, TestingModule } from '@nestjs/testing';
import { SchedulerRegistry } from '@nestjs/schedule';
import {
    INestApplication,
    ValidationPipe,
    LoggerService,
} from '@nestjs/common';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { join, dirname } from 'path';
import * as fs from 'fs';
import { LogService } from '../src/common/log.service';
import { NestExpressApplication } from '@nestjs/platform-express';
import { GlobalExceptionFilter } from '../src/common/filters/global-exception.filter';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import { CacheService } from '../src/common/cache.service';
import { STORAGE_SERVICE } from '../src/product/product.tokens';

process.env.NODE_ENV = 'development';

class MockStorageService {
    async createSignedUploadUrl(input: any) {
        return {
            uploadUrl: `http://localhost:9000/upload/${input.key}`,
            expiresIn: 3600,
            key: input.key,
        };
    }
    async deleteObject(key: string): Promise<void> {
        return;
    }
    buildPublicUrl(key: string): string {
        const normalized = key.replace(/^\/+/, '');
        const targetPath = join(
            __dirname,
            '..',
            'public',
            'uploads',
            normalized,
        );
        const dir = dirname(targetPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        const base64Image =
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
        fs.writeFileSync(targetPath, Buffer.from(base64Image, 'base64'));

        return `/images/${normalized}`;
    }
}

class InMemoryCacheService {
    private readonly values = new Map<string, string>();
    private readonly sets = new Map<string, Set<string>>();

    async set(key: string, val: any) {
        this.values.set(key, JSON.stringify(val));
    }

    async get<T>(key: string): Promise<T | null> {
        const val = this.values.get(key);
        return val ? (JSON.parse(val) as T) : null;
    }

    async getMany<T>(keys: string[]): Promise<Array<T | null>> {
        return Promise.all(keys.map((key) => this.get<T>(key)));
    }

    async del(key: string) {
        this.values.delete(key);
    }

    async addToSet(key: string, member: string): Promise<void> {
        const set = this.sets.get(key) ?? new Set<string>();
        set.add(member);
        this.sets.set(key, set);
    }

    async removeFromSet(key: string, member: string): Promise<void> {
        this.sets.get(key)?.delete(member);
    }

    async getSetMembers(key: string): Promise<string[]> {
        return Array.from(this.sets.get(key) ?? []);
    }

    async setExpire(): Promise<void> {
        return;
    }

    onModuleDestroy() {
        this.values.clear();
        this.sets.clear();
    }
}

// Global counter for unique test data
let testCounter = 0;

export function getUniqueTestData(prefix: string = 'test') {
    const timestamp = Date.now();
    const counter = ++testCounter;
    return {
        email: `${prefix}-${counter}-${timestamp}@test.com`,
        slug: `${prefix}-${counter}-${timestamp}`,
        name: `${prefix} ${counter} ${timestamp}`,
        sku: `${prefix.toUpperCase()}-SKU-${counter}-${timestamp}`,
    };
}

async function cleanDatabase(prisma: PrismaService) {
    // Delete in order of dependency - more comprehensive cleanup
    await prisma.orderItem.deleteMany().catch(() => {});
    await prisma.payment.deleteMany().catch(() => {});
    await prisma.shipment.deleteMany().catch(() => {});
    await prisma.order.deleteMany().catch(() => {});
    await prisma.cartItem.deleteMany().catch(() => {});
    await prisma.cart.deleteMany().catch(() => {});
    await prisma.variantPrice.deleteMany().catch(() => {});
    await prisma.variantInventory.deleteMany().catch(() => {});
    await prisma.productVariant.deleteMany().catch(() => {});
    await prisma.productImage.deleteMany().catch(() => {});
    await prisma.collectionProduct.deleteMany().catch(() => {});
    await prisma.product.deleteMany().catch(() => {});
    await prisma.collection.deleteMany().catch(() => {});
    await prisma.category.deleteMany().catch(() => {});
    await prisma.address.deleteMany().catch(() => {});
    await prisma.passwordResetToken.deleteMany().catch(() => {});
    await prisma.refreshToken.deleteMany().catch(() => {});
    await prisma.user.deleteMany().catch(() => {});
    await prisma.rolePermission.deleteMany().catch(() => {});
    await prisma.permission.deleteMany().catch(() => {});
    await prisma.role.deleteMany().catch(() => {});
    await prisma.outboxEvent.deleteMany().catch(() => {});
    await prisma.webhookProcessingLog.deleteMany().catch(() => {});
    await prisma.dashboardRevenueSnapshot.deleteMany().catch(() => {});
    await prisma.ordersByStatus.deleteMany().catch(() => {});
    await prisma.bestSellingProduct.deleteMany().catch(() => {});
    await prisma.lowStockProduct.deleteMany().catch(() => {});
    await prisma.ordersByLocation.deleteMany().catch(() => {});
    await prisma.orderStatistics.deleteMany().catch(() => {});
    await prisma.customerCounters.deleteMany().catch(() => {});
    await prisma.productsByCategory.deleteMany().catch(() => {});
}

export async function resetE2EDatabase(app: INestApplication) {
    const prisma = app.get<PrismaService>(PrismaService);
    const cacheService = app.get<CacheService>(CacheService);

    await cleanDatabase(prisma);
    cacheService.onModuleDestroy?.();
}

export async function setupE2ETest() {
    const moduleFixture: TestingModule = await Test.createTestingModule({
        imports: [
            AppModule,
            // This module is what allows the test server to serve the uploaded images.
            // It maps the URL path '/images/products' to the physical directory 'public/uploads/products'.
            // ServeStaticModule.forRoot({
            //     // The URL path to serve static files from
            //     serveRoot: '/images/products',
            //     // The physical directory where the files are located
            //     rootPath: join(__dirname, '..', 'public', 'uploads', 'products'),
            // }),
        ],
    })
        .overrideProvider(CacheService)
        .useValue(new InMemoryCacheService())
        .overrideProvider(STORAGE_SERVICE)
        .useClass(MockStorageService)
        .compile();

    const app = moduleFixture.createNestApplication<NestExpressApplication>();

    const logService = app.get(LogService);
    app.useLogger(logService);

    const configService = app.get(ConfigService);
    assertSafeE2EDatabase(configService.get<string>('DATABASE_URL'));

    // Apply the same global configurations as in main.ts
    app.use(cookieParser(configService.get<string>('COOKIE_SECRET')));

    const globalExceptionFilter = new GlobalExceptionFilter(logService);
    app.useGlobalFilters(globalExceptionFilter);

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            transform: true,
            transformOptions: { enableImplicitConversion: true },
        }),
    );

    app.useStaticAssets(join(__dirname, '..', 'public', 'uploads'), {
        prefix: '/images/',
    });
    app.setGlobalPrefix('/api');
    await app.init();

    // Stop background cron jobs to prevent query engine interference during tests
    try {
        const schedulerRegistry = app.get(SchedulerRegistry);
        const cronJobs = schedulerRegistry.getCronJobs();
        cronJobs.forEach((job) => job.stop());
    } catch {}

    const prisma = app.get<PrismaService>(PrismaService);

    await resetE2EDatabase(app);

    return { app, prisma };
}

function assertSafeE2EDatabase(databaseUrl?: string) {
    if (!databaseUrl) {
        throw new Error('DATABASE_URL must be configured before E2E tests run');
    }

    const databaseName = databaseUrl.split('?')[0]?.split('/').pop() ?? '';
    const allowNonTestDb = process.env.E2E_ALLOW_NON_TEST_DB === 'true';

    if (!allowNonTestDb && !/test/i.test(databaseName)) {
        throw new Error(
            `Refusing to clean non-test database "${databaseName}". Use a dedicated test database or set E2E_ALLOW_NON_TEST_DB=true explicitly.`,
        );
    }
}

export async function teardownE2ETest(
    app: INestApplication,
    prisma: PrismaService,
) {
    await cleanDatabase(prisma);
    await app.close();
}
