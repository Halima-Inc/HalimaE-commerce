import { SetMetadata } from '@nestjs/common';

export const REQUIRED_PERMISSIONS_KEY = 'requiredPermissions';

function normalizePermissions(permissions: string[]): string[] {
    return Array.from(
        new Set(
            permissions
                .map((permission) => permission.trim().toLowerCase())
                .filter((permission) => permission.length > 0),
        ),
    );
}

export const RequiredPermissions = (...permissions: string[]) =>
    SetMetadata(REQUIRED_PERMISSIONS_KEY, normalizePermissions(permissions));
