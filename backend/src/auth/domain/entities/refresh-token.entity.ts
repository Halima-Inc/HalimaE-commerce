export class RefreshToken {
    constructor(
        private readonly id: string,
        private readonly tokenHash: string,
        private readonly userId: string,
        private readonly expiresAt: Date,
        private readonly isRevoked: boolean = false,
        private readonly device?: string,
        private readonly ip?: string,
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

    isValid(): boolean {
        return !this.isRevoked && new Date() < this.expiresAt;
    }

    getIsRevoked(): boolean {
        return this.isRevoked;
    }

    getDevice(): string | undefined {
        return this.device;
    }

    getIp(): string | undefined {
        return this.ip;
    }

    getCreatedAt(): Date | undefined {
        return this.createdAt;
    }

    static create(
        id: string,
        tokenHash: string,
        userId: string,
        expiresAt: Date,
        isRevoked: boolean = false,
        device?: string,
        ip?: string,
        createdAt?: Date,
    ): RefreshToken {
        return new RefreshToken(
            id,
            tokenHash,
            userId,
            expiresAt,
            isRevoked,
            device,
            ip,
            createdAt,
        );
    }
}
