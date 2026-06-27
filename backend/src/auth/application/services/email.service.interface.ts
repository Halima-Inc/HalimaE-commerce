export interface IEmailService {
    sendPasswordResetEmail(email: string, token: string): Promise<void>;
    sendWelcomeEmail(email: string, name: string): Promise<void>;
}
