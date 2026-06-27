import {
    Inject,
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { ITokenService } from '../../application/services';
import type { IUserRepository } from '../../domain/interfaces';
import { IS_PUBLIC_KEY } from '../decorators';
import { TOKEN_SERVICE, USER_REPOSITORY } from '../../auth.tokens';

type AuthenticatedUser = {
    userId: string;
    email: string;
    name: string;
    roleId: string | null;
};

type GuardRequest = {
    headers: { authorization?: string };
    user?: AuthenticatedUser;
};

@Injectable()
export class JwtAccessTokenGuard implements CanActivate {
    constructor(
        @Inject(TOKEN_SERVICE)
        private readonly tokenService: ITokenService,
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        private readonly reflector: Reflector,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(
            IS_PUBLIC_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (isPublic) {
            return true;
        }

        const request = context.switchToHttp().getRequest<GuardRequest>();
        const token = this.extractTokenFromHeader(request);

        if (!token) {
            throw new UnauthorizedException('Access token not found');
        }

        try {
            const payload = await this.tokenService.validateAccessToken(token);
            if (!payload?.sub) {
                throw new UnauthorizedException('Invalid access token');
            }

            const user = await this.userRepository.findById(payload.sub);
            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            request.user = {
                userId: user.getId(),
                email: user.getEmail().getValue(),
                name: user.getName(),
                roleId: user.getRoleId(),
            };
            return true;
        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error;
            }

            throw new UnauthorizedException('Failed to validate access token');
        }
    }

    private extractTokenFromHeader(request: GuardRequest): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
