export class CreateRoleCommand {
    constructor(
        public readonly name: string,
        public readonly permissions: string[],
    ) {}
}

export class UpdateRolePermissionsCommand {
    constructor(
        public readonly roleId: string,
        public readonly permissions: string[],
    ) {}
}

export class DeleteRoleCommand {
    constructor(public readonly roleId: string) {}
}
