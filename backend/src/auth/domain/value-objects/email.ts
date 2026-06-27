export class Email {
    constructor(private readonly email: string) {
        if (!this.isValidEmail(email)) {
            throw new Error('Invalid email format');
        }
    }

    getValue(): string {
        return this.email;
    }

    private isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static create(email: string): Email {
        return new Email(email);
    }
}
