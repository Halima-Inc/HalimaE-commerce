import { RefreshToken } from '../entities';

export interface IRefreshTokenRepository {
    save(token: RefreshToken): Promise<void>;
    findByTokenHash(tokenHash: string): Promise<RefreshToken | null>;
    findByUserId(userId: string): Promise<RefreshToken[]>;
    update(token: RefreshToken): Promise<void>;
    delete(id: string): Promise<void>;
}
