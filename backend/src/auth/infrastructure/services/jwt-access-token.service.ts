import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '../../domain';
import { ITokenService } from '../../application/services';

@Injectable()
export class JwtAccessTokenService implements ITokenService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {}

    async generateAccessToken(user: User): Promise<string> {
        const accessTokenTtl = this.configService.get<string>(
            'JWT_ACCESS_EXPIRES_IN',
            '20m',
        );
        const jwtSecret = this.configService.get<string>('JWT_SECRET');

        const payload = {
            sub: user.getId(),
            email: user.getEmail().getValue(),
            name: user.getName(),
            roleId: user.getRoleId(),
        };

        return this.jwtService.signAsync(payload as any, {
            expiresIn: accessTokenTtl as any,
            secret: jwtSecret,
        });
    }

    async validateAccessToken(token: string): Promise<any | null> {
        const jwtSecret = this.configService.get<string>('JWT_SECRET');

        try {
            return await this.jwtService.verifyAsync(token, {
                secret: jwtSecret,
            });
        } catch {
            return null;
        }
    }

    async decodeAccessToken(token: string): Promise<any | null> {
        try {
            return this.jwtService.decode(token);
        } catch {
            return null;
        }
    }
}
