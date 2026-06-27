export class Role {
    private static readonly PROTECTED_ROLE_NAMES = new Set([
        'admin',
        'customer',
    ]);

    constructor(
        private readonly id: string,
        private readonly name: string,
        private readonly permissions?: string[],
    ) {}

    getId(): string {
        return this.id;
    }

    getName(): string {
        return this.name;
    }

    getPermissions(): string[] | undefined {
        return this.permissions;
    }

    hasPermission(permission: string): boolean {
        const normalizedPermission = permission.trim().toLowerCase();
        return (
            this.permissions?.some(
                (value) => value.trim().toLowerCase() === normalizedPermission,
            ) ?? false
        );
    }

    isProtected(): boolean {
        return Role.isProtectedRoleName(this.name);
    }

    static isProtectedRoleName(roleName: string): boolean {
        return Role.PROTECTED_ROLE_NAMES.has(roleName.trim().toLowerCase());
    }

    static getProtectedRoleNames(): string[] {
        return Array.from(Role.PROTECTED_ROLE_NAMES);
    }

    static create(id: string, name: string, permissions?: string[]): Role {
        const normalizedPermissions = permissions?.map((permission) =>
            permission.trim().toLowerCase(),
        );

        return new Role(id, name.trim().toLowerCase(), normalizedPermissions);
    }
}
