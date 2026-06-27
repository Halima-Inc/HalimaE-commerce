import { Inject, Injectable } from '@nestjs/common';
import { UpdateRolePermissionsCommand } from '../commands';
import {
    ProtectedRoleException,
    RoleNotFoundException,
} from '../../domain/exceptions';
import type { Role } from '../../domain/entities';
import type { IRoleRepository } from '../../domain/interfaces';
import { ROLE_REPOSITORY } from '../../auth.tokens';

@Injectable()
export class UpdateRolePermissionsHandler {
    constructor(
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async execute(command: UpdateRolePermissionsCommand): Promise<Role> {
        const role = await this.roleRepository.findById(command.roleId, {
            includePermissions: false,
        });
        if (!role) {
            throw new RoleNotFoundException('Role not found');
        }

        if (role.isProtected()) {
            throw new ProtectedRoleException(
                `Role ${role.getName()} is protected and cannot be edited`,
            );
        }

        const normalizedPermissions = command.permissions
            .map((permission) => permission.trim().toLowerCase())
            .filter((permission) => permission.length > 0);

        return this.roleRepository.updatePermissions(
            command.roleId,
            normalizedPermissions,
        );
    }
}
