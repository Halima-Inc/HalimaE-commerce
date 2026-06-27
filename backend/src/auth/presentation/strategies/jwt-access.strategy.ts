import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { IUserRepository } from '../../domain/interfaces';
import { Inject } from '@nestjs/common';
import { USER_REPOSITORY } from '../../auth.tokens';

@Injectable()
export class JwtAccessTokenStrategy extends PassportStrategy(
    Strategy,
    'jwt-access',
) {
    constructor(
        private readonly configService: ConfigService,
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.get<string>('JWT_SECRET') as string,
        });
    }

    async validate(payload: any) {
        if (!payload?.sub) {
            return null;
        }

        const user = await this.userRepository.findById(payload.sub);
        if (!user) {
            return null;
        }

        return {
            userId: user.getId(),
            email: user.getEmail().getValue(),
            name: user.getName(),
            roleId: user.getRoleId(),
        };
    }
}
