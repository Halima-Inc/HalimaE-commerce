import { Inject, Injectable } from '@nestjs/common';
import { CreateRoleCommand } from '../commands';
import {
    ProtectedRoleException,
    Role,
    RoleAlreadyExistsException,
} from '../../domain';
import type { IRoleRepository } from '../../domain/interfaces';
import { ROLE_REPOSITORY } from '../../auth.tokens';

@Injectable()
export class CreateRoleHandler {
    constructor(
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async execute(command: CreateRoleCommand): Promise<Role> {
        const roleName = command.name.trim().toLowerCase();
        if (Role.isProtectedRoleName(roleName)) {
            throw new ProtectedRoleException(
                `Role ${roleName} is protected and cannot be created through this endpoint`,
            );
        }

        const existingRole = await this.roleRepository.findByName(roleName, {
            includePermissions: false,
        });
        if (existingRole) {
            throw new RoleAlreadyExistsException(
                `Role ${roleName} already exists`,
            );
        }

        const permissions = command.permissions
            .map((permission) => permission.trim().toLowerCase())
            .filter((permission) => permission.length > 0);

        return this.roleRepository.create(roleName, permissions);
    }
}
