import { PasswordResetToken } from '../entities';

export interface IPasswordResetTokenRepository {
    save(token: PasswordResetToken): Promise<void>;
    findByTokenHash(tokenHash: string): Promise<PasswordResetToken | null>;
    findByUserId(userId: string): Promise<PasswordResetToken | null>;
    delete(id: string): Promise<void>;
}
