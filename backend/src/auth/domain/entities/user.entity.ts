import { EncryptedPassword, Email } from '../value-objects';

export class User {
    constructor(
        private readonly id: string,
        private readonly email: Email,
        private readonly name: string,
        private readonly passwordHash: EncryptedPassword,
        private readonly roleId: string | null,
        private readonly phone?: string,
        private readonly provider?: string,
        private readonly providerId?: string,
        private readonly status?: string,
        private readonly createdAt?: Date,
        private readonly updatedAt?: Date,
    ) {}

    getId(): string {
        return this.id;
    }

    getEmail(): Email {
        return this.email;
    }

    getName(): string {
        return this.name;
    }

    getPasswordHash(): EncryptedPassword {
        return this.passwordHash;
    }

    getRoleId(): string | null {
        return this.roleId;
    }

    getPhone(): string | undefined {
        return this.phone;
    }

    getProvider(): string | undefined {
        return this.provider;
    }

    getProviderId(): string | undefined {
        return this.providerId;
    }

    getStatus(): string | undefined {
        return this.status;
    }

    getCreatedAt(): Date | undefined {
        return this.createdAt;
    }

    getUpdatedAt(): Date | undefined {
        return this.updatedAt;
    }

    static create(
        id: string,
        email: Email,
        name: string,
        passwordHash: EncryptedPassword,
        roleId: string | null = null,
        phone?: string,
        provider?: string,
        providerId?: string,
        status?: string,
        createdAt?: Date,
        updatedAt?: Date,
    ): User {
        return new User(
            id,
            email,
            name,
            passwordHash,
            roleId,
            phone,
            provider,
            providerId,
            status,
            createdAt,
            updatedAt,
        );
    }
}
