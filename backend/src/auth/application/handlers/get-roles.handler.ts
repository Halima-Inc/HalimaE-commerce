import { Inject, Injectable } from '@nestjs/common';
import type { Role } from '../../domain';
import type { IRoleRepository } from '../../domain/interfaces';
import { ROLE_REPOSITORY } from '../../auth.tokens';

@Injectable()
export class GetRolesHandler {
    constructor(
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
    ) {}

    async execute(): Promise<Role[]> {
        return this.roleRepository.findAllEditable();
    }
}
