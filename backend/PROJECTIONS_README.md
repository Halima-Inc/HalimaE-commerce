Dashboard Projections — Quick Start

What changed
- Added denormalized projection models in `prisma/schema.prisma` for fast dashboard reads.
- Added a `PrismaProjectionRepository` and projector classes that update projections from Order/Payment events.

Apply the database migration
1. Generate and apply a migration locally (recommended in dev):

```bash
npx prisma migrate dev --name add-dashboard-projections
npx prisma generate
```

2. If you prefer to push schema without a migration (not recommended for production):

```bash
npx prisma db push
npx prisma generate
```

Run unit tests (projector specs included)

```bash
# from backend/
npm run test:unit
```

Notes
- The projectors are idempotent and safe to run multiple times; consider running a replay to backfill projections from historical outbox events.
- After migrating and validating projections, you can switch dashboard reads to use the projection tables and remove polling.