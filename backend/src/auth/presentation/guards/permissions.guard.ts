import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Inject,
    Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Role } from '../../domain/entities';
import { REQUIRED_PERMISSIONS_KEY } from '../decorators';
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
export class PermissionsGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
            REQUIRED_PERMISSIONS_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!requiredPermissions?.length) {
            return true;
        }

        const request = context.switchToHttp().getRequest<GuardRequest>();
        const user = request.user;

        if (!user?.roleId) {
            throw new ForbiddenException('User not found in request');
        }

        let role: Role | null | undefined = request.authRole;

        if (
            !role ||
            (role.getName().toLowerCase() !== 'admin' &&
                !role.getPermissions()?.length)
        ) {
            role = await this.roleRepository.findById(user.roleId, {
                includePermissions: true,
            });
        }

        if (!role) {
            throw new ForbiddenException('User role not found');
        }

        request.authRole = role;

        if (role.getName().toLowerCase() === 'admin') {
            return true;
        }

        const hasAllPermissions = requiredPermissions.every((permission) =>
            role.hasPermission(permission),
        );

        if (!hasAllPermissions) {
            throw new ForbiddenException(
                'Insufficient permissions for this resource',
            );
        }

        return true;
    }
}
