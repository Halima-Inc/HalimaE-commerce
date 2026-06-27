export class PasswordResetToken {
    constructor(
        private readonly id: string,
        private readonly tokenHash: string,
        private readonly userId: string,
        private readonly expiresAt: Date,
        private readonly createdAt?: Date,
    ) {}

    getId(): string {
        return this.id;
    }

    getTokenHash(): string {
        return this.tokenHash;
    }

    getUserId(): string {
        return this.userId;
    }

    getExpiresAt(): Date {
        return this.expiresAt;
    }

    isExpired(): boolean {
        return new Date() > this.expiresAt;
    }

    getCreatedAt(): Date | undefined {
        return this.createdAt;
    }

    static create(
        id: string,
        tokenHash: string,
        userId: string,
        expiresAt: Date,
        createdAt?: Date,
    ): PasswordResetToken {
        return new PasswordResetToken(
            id,
            tokenHash,
            userId,
            expiresAt,
            createdAt,
        );
    }
}
