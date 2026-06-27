export class EncryptedPassword {
    constructor(private readonly hashedPassword: string) {}

    getHashedPassword(): string {
        return this.hashedPassword;
    }

    static create(hashedPassword: string): EncryptedPassword {
        return new EncryptedPassword(hashedPassword);
    }
}
