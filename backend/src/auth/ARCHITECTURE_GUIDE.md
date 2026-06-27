# Onion Architecture Refactor - Complete Guide

## 📋 Overview

This document guides you through the refactored auth system following **Onion (Hexagonal) Architecture** principles:
- Pure business logic in Domain layer (no external dependencies)
- Use cases in Application layer
- External concerns (ORM, HTTP, Crypto) in Infrastructure
- HTTP endpoints in Presentation layer

## 🏗️ Architecture Layers

### 1. Domain Layer (`domain/`)
**Purpose:** Pure business logic, completely framework/library agnostic

```
domain/
├── entities/
│   ├── user.entity.ts          # User aggregate root
│   ├── role.entity.ts          # Role aggregate
│   ├── refresh-token.entity.ts # Token domain model
│   └── password-reset-token.entity.ts
├── interfaces/
│   ├── user.repository.interface.ts      # ← Domain defines repository interface
│   ├── role.repository.interface.ts
│   ├── refresh-token.repository.interface.ts
│   └── password-reset-token.repository.interface.ts
├── value-objects/
│   ├── email.ts               # Validates email format
│   └── encrypted-password.ts  # Encapsulates password concept
└── exceptions/
    └── auth.exceptions.ts     # Domain-specific errors
```

**Key Point:** No Prisma, no HTTP, no frameworks. Just pure entities.

```typescript
// Domain is completely ignorant of how data is persisted
export class User {
    constructor(
        private readonly id: string,
        private readonly email: Email,
        private readonly name: string,
        private readonly passwordHash: EncryptedPassword,
        // ... no Prisma imports!
    ) {}
}
```

### 2. Application Layer (`application/`)
**Purpose:** Use cases, commands/queries, application services

```
application/
├── commands/
│   ├── auth.commands.ts       # Command objects (data transfer)
│   └── index.ts
├── queries/
│   ├── auth.queries.ts        # Query objects
│   └── index.ts
├── handlers/
│   ├── register-user.handler.ts     # Command handler = use case
│   ├── login-user.handler.ts
│   ├── refresh-token.handler.ts
│   ├── reset-password.handler.ts
│   └── index.ts
├── dtos/
│   ├── auth.dto.ts            # Application DTOs (not HTTP DTOs)
│   └── index.ts
└── services/
    ├── password.service.interface.ts     # ← Application defines interface
    ├── token.service.interface.ts        # ← Delegates to Infrastructure
    ├── refresh-token.service.interface.ts
    ├── email.service.interface.ts
    └── index.ts
```

**Key Point:** Orchestrates domain entities. One-way dependency: Application → Domain

```typescript
// Handler uses domain entities and asks infrastructure for services
export class RegisterUserHandler {
    async execute(command: RegisterUserCommand): Promise<User> {
        // Check business rule: user must not exist
        const existing = await this.userRepository.findByEmail(command.email);
        if (existing) throw new UserAlreadyExistsException();
        
        // Create domain entity
        const user = User.create(id, email, name, passwordHash, roleId);
        
        // Persist through repository
        await this.userRepository.save(user);
        return user;
    }
}
```

### 3. Infrastructure Layer (`infrastructure/`)
**Purpose:** Implements domain interfaces, provides external services

```
infrastructure/
├── repositories/
│   ├── prisma-user.repository.ts      # ← Implements IUserRepository
│   ├── prisma-role.repository.ts
│   ├── prisma-refresh-token.repository.ts
│   ├── prisma-password-reset-token.repository.ts
│   └── index.ts
├── services/
│   ├── bcrypt-password.service.ts           # ← Implements IPasswordService
│   ├── jwt-access-token.service.ts          # ← Implements ITokenService
│   ├── jwt-refresh-token.service.ts         # ← Implements IRefreshTokenService
│   ├── mailer-email.service.ts              # ← Implements IEmailService
│   └── index.ts
└── strategies/
    └── jwt-access.strategy.ts  # Passport strategy (HTTP middleware)
```

**Key Point:** Everything here imports external libraries (Prisma, JWT, bcrypt, etc.)

```typescript
// Infrastructure implements domain interfaces
@Injectable()
export class PrismaUserRepository implements IUserRepository {
    async save(user: User): Promise<void> {
        // Convert domain entity to Prisma model
        await this.prisma.user.create({
            data: {
                id: user.getId(),
                email: user.getEmail().getValue(),
                // ... persistence details
            }
        });
    }
}
```

### 4. Presentation Layer (`presentation/`)
**Purpose:** HTTP controllers, guards, decorators, request/response DTOs

```
presentation/
├── controllers/
│   ├── auth.controller.ts      # HTTP endpoints
│   └── index.ts
├── guards/
│   ├── jwt-access-token.guard.ts    # ← Validates Bearer tokens
│   ├── roles.guard.ts               # ← Checks role-based access
│   └── index.ts
├── decorators/
│   ├── public.decorator.ts          # Marks routes as public
│   ├── required-roles.decorator.ts  # Specifies required roles
│   ├── current-user.decorator.ts    # Extracts user from request
│   └── index.ts
├── dtos/
│   ├── auth.dto.ts            # HTTP DTOs (Request/Response)
│   └── index.ts
├── strategies/
│   ├── jwt-access.strategy.ts  # Passport strategy
│   └── index.ts
└── index.ts
```

**Key Point:** Contains ALL HTTP concerns (Express, NestJS HTTP, decorators)

```typescript
@Controller('auth')
export class AuthController {
    @Post('login')
    @Public() // ← Presentation decorator
    async login(
        @Body() dto: LoginUserRequestDto, // ← HTTP DTO
        @Res({ passthrough: true }) res: Response, // ← HTTP Response
    ) {
        const result = await this.loginUserHandler.execute({...}); 
        return result; // ← Presentation DTO
    }
}
```

## 📊 Dependency Flow

```
Presentation
    ↓ (depends on)
Application
    ↓ (depends on)
Domain
    ↓ (defines)
Interfaces (Repository, Services)
    ↑ (implemented by)
Infrastructure
```

**Golden Rule:** Never go sideways or backwards:
- ✅ Presentation → Application
- ✅ Application → Domain  
- ✅ Infrastructure → Domain
- ❌ Domain → Presentation
- ❌ Domain → Infrastructure
- ❌ Application → Infrastructure (only through interfaces)

## 🚀 Usage Flow

### User Registration

```
HTTP Request (POST /auth/register)
    ↓
Presentation: AuthController.register()
    ├─ Validates HTTP DTO
    ├─ Extracts data
    ├─ Calls Application Handler
    ↓
Application: RegisterUserHandler.execute(RegisterUserCommand)
    ├─ Checks domain rules (user exists? role exists?)
    ├─ Creates Domain Entity: User
    ├─ Calls Infrastructure: userRepository.save(user)
    ├─ Calls Infrastructure: passwordService.hash()
    ↓
Domain: User Entity (business logic)
    └─ No external calls, pure logic
    ↓
Infrastructure
    ├─ BcryptPasswordService: hashes password
    ├─ PrismaUserRepository: saves to database
    └─ Returns to Application
    ↓
Application: Returns User to Presentation
    ↓
Presentation: Maps to Response DTO, returns to HTTP client
```

## 🔐 Auth Guard Placement: Presentation Layer

See [AUTH_GUARD_PLACEMENT.md](./AUTH_GUARD_PLACEMENT.md) for detailed explanation.

**Why Presentation:**

```
HTTP Request Header: Authorization: Bearer xyz123
    ↓
Presentation: JwtAccessTokenGuard
    ├─ Extract token from header (HTTP concern) ✓
    ├─ Call Application: ITokenService.validateToken()
    ├─ Attach user to request (HTTP concern) ✓
    └─ Decide: allow or reject request
    ↓
If allowed → Controller → Handler → Domain
If rejected → 401 Unauthorized (HTTP response)
```

Guards are **HTTP gatekeepers**, not business logic.

## 📁 File Structure Reference

```
src/auth/
├── domain/
│   ├── entities/          # Business models
│   ├── interfaces/        # Repository interfaces
│   ├── exceptions/        # Domain errors
│   ├── value-objects/     # Value objects
│   └── index.ts
├── application/
│   ├── commands/          # Command objects
│   ├── queries/           # Query objects
│   ├── handlers/          # Use case implementations
│   ├── dtos/              # Application DTOs
│   ├── services/          # Service interfaces
│   └── index.ts
├── infrastructure/
│   ├── repositories/      # Repository implementations
│   ├── services/          # Service implementations
│   ├── strategies/        # Passport strategies
│   └── index.ts
├── presentation/
│   ├── controllers/       # HTTP controllers
│   ├── guards/            # HTTP guards
│   ├── decorators/        # HTTP decorators
│   ├── dtos/              # HTTP DTOs
│   ├── strategies/        # Passport strategies
│   └── index.ts
├── auth.module.ts         # Dependency injection
└── index.ts
```

## 🔧 Dependency Injection (auth.module.ts)

```typescript
@Module({
    providers: [
        // Presentation layer
        JwtAccessTokenGuard,
        RolesGuard,
        JwtAccessTokenStrategy,
        
        // Application layer (handlers)
        RegisterUserHandler,
        LoginUserHandler,
        RefreshTokenHandler,
        
        // Infrastructure services
        BcryptPasswordService,
        JwtAccessTokenService,
        JwtRefreshTokenService,
        
        // Repository binding (Dependency Inversion)
        {
            provide: IUserRepository,
            useClass: PrismaUserRepository,  // ← Plug in Prisma implementation
        },
        // ... more repository bindings
    ]
})
```

**Key:** Repositories and services are registered by **interface**, not concrete class.
This allows easy swapping of implementations (e.g., MongoDB later).

## ⚙️ Configuration & Environment

Required environment variables:

```env
# Database
DATABASE_URL=postgresql://...

# JWT tokens
JWT_SECRET=your-secret-key
JWT_REFRESH_SECRET=your-refresh-secret-key

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Frontend
FRONTEND_URL=http://localhost:3000

# Environment
NODE_ENV=development
```

## 🎯 Next Steps for Completion

- [ ] Migrate `customer/` endpoints to use new `User` model
- [ ] Migrate `cart/`, `order/` to reference `userId` instead of `customerId`
- [ ] Update all services that depend on `Customer` table
- [ ] Create database migration to consolidate data
- [ ] Update tests to use new structure
- [ ] Update Swagger/API documentation
- [ ] Deploy with new schema

## 📚 Testing Strategy

```
Domain Layer Tests
    └─ Pure entity logic, no mocks needed
    └─ Value object validation
    └─ Exception handling

Application Layer Tests
    └─ Mock repositories
    └─ Mock external services
    └─ Test use cases in isolation
    └─ Test business rules

Infrastructure Tests
    └─ Integration tests with real database
    └─ Service implementations

Presentation Tests
    └─ Controller tests
    └─ Guard tests (mock application services)
    └─ DTO validation
```

## 🚨 Common Mistakes to Avoid

❌ **Don't:** Import Prisma in domain entities
```typescript
// WRONG
export class User {
    constructor(private prisma: PrismaService) { }
}
```

✅ **Do:** Keep domain pure, implement interfaces in infrastructure
```typescript
// RIGHT - Domain doesn't know about persistence
export class User {
    constructor(private readonly email: Email) { }
}

// Infrastructure implements the interface
export class PrismaUserRepository implements IUserRepository {
    save(user: User) { /* Prisma logic */ }
}
```

❌ **Don't:** Put HTTP concerns in application handlers
```typescript
// WRONG
export class RegisterUserHandler {
    execute(req: Request): User { } // HTTP object in domain logic
}
```

✅ **Do:** Keep handlers pure, adapt in controllers
```typescript
// RIGHT - Handler is HTTP-agnostic
export class RegisterUserHandler {
    execute(command: RegisterUserCommand): User { }
}

// Controller handles HTTP
@Controller()
register(@Body() dto: RegisterUserRequestDto) {
    return this.handler.execute(/* extract command from DTO */);
}
```

❌ **Don't:** Have circular dependencies
```typescript
// WRONG - Application depends on Infrastructure
export class Handler {
    constructor(private repo: PrismaUserRepository) { }
}
```

✅ **Do:** Use interface-based dependency injection
```typescript
// RIGHT - Application depends on interface
export class Handler {
    constructor(private repo: IUserRepository) { }
}
```

## 📖 References

- [Onion Architecture](https://jeffreypalermo.com/2008/07/the-onion-architecture-part-1/)
- [Hexagonal Architecture](https://www.happycoders.eu/software-architecture/hexagonal-architecture/)
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
- [NestJS Best Practices](https://docs.nestjs.com/techniques/pipes)
