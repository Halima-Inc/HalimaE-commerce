# Halima E-Commerce Backend Service

A high-performance e-commerce API built with NestJS, Prisma, and PostgreSQL. This service powers product catalogs, persistence carts, order lifecycles, analytical dashboards, and payment gateway integrations.

## Core Architectural Concepts

The service is structured according to strict architectural guidelines to ensure separation of concerns, high testability, and technology independence.

### Onion Architecture (Clean Architecture)
The backend codebase strictly follows the Onion Architecture. Core business logic is shielded from external delivery and framework layers.
- Domain Layer (src/category/domain, src/auth/domain, etc.): Defines the aggregate roots, entities, domain exceptions, and repository interfaces (contracts). This layer is entirely pure and free of ORM (Prisma) or framework (NestJS) imports.
- Application Layer (src/category/application, src/auth/application, etc.): Coordinates domain entities to execute specific use cases. Uses commands and queries, with one handler per use case. Accesses infrastructure services only through interfaces.
- Infrastructure Layer (src/category/infrastructure, src/auth/infrastructure, etc.): Implements application and domain interfaces. Houses Prisma repository implementations, payment adapters, object storage clients, and encryption services.
- Presentation Layer (src/category/presentation, src/auth/presentation, etc.): Manages request delivery. Houses HTTP controllers, custom guards, decorators, and request validation DTOs.

### Transactional Outbox Design Pattern
To ensure atomic consistency and reliable message delivery without coupling modules, the service employs a Transactional Outbox design pattern.
- Whenever an operation changes state and requires notification of other modules (for example, Capturing a Payment), the event is saved to the Outbox table in the database as part of the same ACID transaction.
- Background publishers dispatch outbox events to interested modules (e.g. updating Order payment status asynchronously).
- This decouples the database transaction boundary from external event subscribers.

### Real-Time Projections and Dynamic Fallbacks
The analytical dashboard fetches aggregated views from projection tables (such as SalesByPeriod, OrdersByStatus, LowStockProduct) for optimized response times. If projections are empty (e.g., in developer or fresh seeding environments), the Dashboard Service dynamically aggregates database metrics across Order Items, Users, and Product Variants directly from database tables using secure Prisma queries, ensuring seamless local developer testing.

---

## Infrastructure Dependencies

This project relies on the following infrastructure dependencies, configured via environment variables. Refer to the env.example file for exact configuration names:

1. PostgreSQL
   - Primary database storing the application state.
   - Migrations are managed via Prisma migrate.

2. Redis
   - Serves as the caching backend and rate-limiter storage to optimize analytical queries and prevent API abuse.

3. Object Storage (AWS S3 or MinIO)
   - Stores media and images for product variants.
   - Configures connection endpoint, bucket name, and access keys.

4. Paymob Payment Gateway
   - Integrates digital wallets and credit card processing.
   - Validates Paymob webhook callbacks using HMAC signature verification secrets.

5. SMTP Mail Server
   - Dispatches transactional emails (user welcome, checkout invoice, password resets) using secure SMTP credentials.

6. Google OAuth Client
   - Handles social credentials verification for customer single sign-on flows.

---

## Environment Setup

Create a .env file in the backend root directory using .env.example as a template:

```bash
cp .env.example .env
```

Define the configuration values:
- DATABASE_URL: PostgreSQL database connection string.
- REDIS_HOST, REDIS_PORT: Redis connection details.
- AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET: Storage coordinates.
- PAYMOB_API_KEY, PAYMOB_HMAC_SECRET: Paymob payment secrets.
- SMTP_HOST, SMTP_USER, SMTP_PASS: Mail server credentials.

---

## Database Management

Manage the schema and migrations using the following Prisma commands:

```bash
# Generate Prisma client
npx prisma generate

# Apply migrations to database
npx prisma migrate deploy

# Seed initial roles and administrative users
npm run db:seed

# Reset database (Development only - destructive)
npx prisma migrate reset

# Open Prisma Studio to browse tables
npx prisma studio
```

---

## Development and Production Execution

```bash
# Install dependencies
npm install

# Run in development watch mode
npm run start:dev

# Run in debug mode
npm run start:debug

# Build production bundle
npm run build

# Run production server
npm run start:prod
```

Once running, the API documentation is available at:
- Swagger Documentation: http://localhost:3000/api/docs
- OpenAPI JSON: http://localhost:3000/api/docs-json

---

## Testing Strategy

The backend has extensive E2E testing to verify authentication, carts, categories, dashboard computations, orders, products, and payment processing under real-world scenarios.

### E2E Test Setup and Parallel Execution
- The E2E tests are configured to run in parallel without database cross-contamination.
- Each test run executes on isolated schemas, reset automatically between test specs.
- The `cleanDatabase` function in `jest-e2e.setup.ts` truncates all operational and projection tables between tests.

Run tests using the following commands:

```bash
# Run unit tests
npm run test

# Run all E2E tests
npm run test:e2e

# Run a specific test suite (e.g. dashboard)
npx jest --config ./test/jest-e2e.json dashboard.e2e-spec.ts

# Run tests with coverage
npm run test:cov
```

---

## Code Quality

```bash
# Lint code
npm run lint

# Format code files
npm run format
```
