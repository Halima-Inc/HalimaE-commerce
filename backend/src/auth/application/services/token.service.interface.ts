import { User } from '../../domain';

export interface ITokenService {
    generateAccessToken(user: User): Promise<string>;
    validateAccessToken(token: string): Promise<any | null>;
    decodeAccessToken(token: string): Promise<any | null>;
}
