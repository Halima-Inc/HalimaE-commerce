# Halima E-Commerce Platform

A production-ready e-commerce platform featuring a NestJS backend and a Next.js frontend. This monorepo implements a high-performance shopping, checkout, and inventory tracking system built with modern architectural patterns.

## Repository Structure

The project is divided into two primary directories:
- /backend: A NestJS backend API implementing Onion Architecture, the Transactional Outbox pattern, Prisma ORM, and database-safe metrics calculations.
- /frontend: A Next.js web application providing client interface, catalog browsing, cart operations, checkout processing, and dashboard visualization.

## Architecture and Core Design Patterns

### Onion Architecture (Clean Architecture)
The backend is structured into concentric layers to isolate business policies from delivery and infrastructure details:
- Domain Layer: Contains pure business entities, value objects, domain exceptions, and repository interface definitions. It has no external framework dependencies.
- Application Layer: Contains the core use cases, query/command handlers, DTO definitions, and application-level service interfaces.
- Infrastructure Layer: Holds technology-specific adapters including Prisma ORM repositories, Redis cache stores, AWS S3 storage services, and JWT encoders.
- Presentation Layer: Manages incoming HTTP requests, controllers, request-validation DTOs, route guards, and Swagger/OpenAPI specifications.

This inward-only dependency direction ensures that database or library changes do not alter core business rules.

### Transactional Outbox Pattern
To prevent data inconsistency and ensure robust cross-module communication, the platform employs a Transactional Outbox pattern. 
- For instance, when a Payment is successfully captured, the event is saved to the database as part of the database transaction.
- Background publishers read and dispatch the events to consumers (such as the Order module's payment status updater) to achieve eventually consistent transitions without blocking synchronous HTTP response loops.

### Projections and Fallbacks
The analytical dashboard uses projections for high-performance retrieval of aggregated statistics (revenue snapshots, best sellers, low-stock warnings, and geographical data). When projections are not yet built or are empty during development, the system automatically falls back to dynamically aggregated database queries that avoid memory-intensive Prisma aggregations.

## Infrastructure and External Dependencies

The platform requires the following service dependencies, configured via environment variables:

1. PostgreSQL
   - Primary database storing products, categories, orders, users, and outbox logs.
   - Connected via Prisma client.

2. Redis
   - Used for caching analytical projections, session tracking, and rate limiting to optimize API performance.

3. AWS S3 or MinIO
   - Object storage for product and variant images.
   - Allows uploading, signing, and serving product variant images safely.

4. Paymob
   - Payment gateway integration for card payments, mobile wallets, and webhook transaction validation.

5. SMTP Server
   - Transactional mail delivery for user registration, checkout confirmations, and password reset procedures.

6. Google OAuth
   - Configures social authentication flows for customer registrations and single sign-ons.

## Getting Started

Refer to the individual README documents inside `/backend` and `/frontend` for detailed setup, testing, and environment configuration instructions.
- Backend Setup: [backend/README.md](./backend/README.md)
- Frontend Setup: [frontend/README.md](./frontend/README.md)
