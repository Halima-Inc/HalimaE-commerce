import { Inject, Injectable } from '@nestjs/common';
import { DeleteRoleCommand } from '../commands';
import {
    ProtectedRoleException,
    RoleNotFoundException,
} from '../../domain/exceptions';
import type { IRoleRepository } from '../../domain/interfaces';
import { ROLE_REPOSITORY } from '../../auth.tokens';

@Injectable()
export class DeleteRoleHandler {
    constructor(
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async execute(command: DeleteRoleCommand): Promise<void> {
        const role = await this.roleRepository.findById(command.roleId, {
            includePermissions: false,
        });
        if (!role) {
            throw new RoleNotFoundException('Role not found');
        }

        if (role.isProtected()) {
            throw new ProtectedRoleException(
                `Role ${role.getName()} is protected and cannot be deleted`,
            );
        }

        await this.roleRepository.delete(command.roleId);
    }
}
