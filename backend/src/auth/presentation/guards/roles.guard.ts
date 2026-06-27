import {
    Inject,
    Injectable,
    CanActivate,
    ExecutionContext,
    ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Role } from '../../domain/entities';
import { REQUIRED_ROLES_KEY } from '../decorators';
import type { IRoleRepository } from '../../domain/interfaces';
import { ROLE_REPOSITORY } from '../../auth.tokens';

type AuthenticatedUser = {
    userId: string;
    email: string;
    name: string;
    roleId: string | null;
};

type GuardRequest = {
    user?: AuthenticatedUser;
    authRole?: Role;
};

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
            REQUIRED_ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!requiredRoles || requiredRoles.length === 0) {
            return true;
        }

        const request = context.switchToHttp().getRequest<GuardRequest>();
        const user = request.user;

        if (!user || !user.roleId) {
            throw new ForbiddenException('User not found in request');
        }

        const userRole =
            request.authRole ??
            (await this.roleRepository.findById(user.roleId, {
                includePermissions: false,
            }));

        if (!userRole) {
            throw new ForbiddenException('User role not found');
        }

        request.authRole = userRole;

        if (requiredRoles.includes(userRole.getName().toLowerCase())) {
            return true;
        }

        throw new ForbiddenException(
            'Insufficient permissions for this resource',
        );
    }
}
