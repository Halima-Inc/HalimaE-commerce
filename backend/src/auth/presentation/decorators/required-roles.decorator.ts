import { SetMetadata } from '@nestjs/common';

export const REQUIRED_ROLES_KEY = 'requiredRoles';

function normalizeRoles(roles: string[]): string[] {
    return Array.from(
        new Set(
            roles
                .map((role) => role.trim().toLowerCase())
                .filter((role) => role.length > 0),
        ),
    );
}

export const RequiredRoles = (...roles: string[]) =>
    SetMetadata(REQUIRED_ROLES_KEY, normalizeRoles(roles));
