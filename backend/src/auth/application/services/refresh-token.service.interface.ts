import { User } from '../../domain';

export interface IRefreshTokenService {
    generateRefreshToken(user: User): Promise<string>;
    validateRefreshToken(token: string): Promise<any | null>;
    revokeToken(token: string): Promise<void>;
}
