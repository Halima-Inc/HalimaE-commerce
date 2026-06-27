import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { CacheService } from '../../../common/cache.service';
import { Role } from '../../domain/entities';
import { IRoleRepository, RoleLookupOptions } from '../../domain/interfaces';

type RoleRecord = {
    id: string;
    name: string;
    permissions?: Array<{ permission: { name: string } }>;
};

type RoleCacheDto = {
    id: string;
    name: string;
    permissions?: string[];
};

@Injectable()
export class PrismaRoleRepository implements IRoleRepository {
    private readonly roleByIdPrefix = 'auth:role:id:';
    private readonly roleByNamePrefix = 'auth:role:name:';
    private readonly roleEditableListKey = 'auth:roles:editable';
    private readonly roleListKey = 'auth:roles:all';
    private readonly roleCacheTtlSec = 60 * 30;

    constructor(
        private readonly prisma: PrismaService,
        private readonly cacheService: CacheService,
    ) {}

    async findById(
        id: string,
        options: RoleLookupOptions = {},
    ): Promise<Role | null> {
        const includePermissions = options.includePermissions ?? true;
        const cacheKey = this.getRoleByIdKey(id, includePermissions);
        const cached = await this.cacheService.get<RoleCacheDto>(cacheKey);
        if (cached) {
            return this.toDomainFromCache(cached);
        }

        const roleRecord = includePermissions
            ? await this.findRoleRecordByIdWithPermissions(id)
            : await this.findRoleRecordByIdLean(id);

        if (!roleRecord) {
            return null;
        }

        const roleCacheDto = this.toCacheDto(roleRecord);
        await Promise.all([
            this.cacheService.set(cacheKey, roleCacheDto, this.roleCacheTtlSec),
            this.cacheService.set(
                this.getRoleByNameKey(roleRecord.name, includePermissions),
                roleCacheDto,
                this.roleCacheTtlSec,
            ),
        ]);

        return this.toDomain(roleRecord);
    }

    async findByName(
        name: string,
        options: RoleLookupOptions = {},
    ): Promise<Role | null> {
        const normalizedName = name.trim().toLowerCase();
        const includePermissions = options.includePermissions ?? true;
        const cacheKey = this.getRoleByNameKey(
            normalizedName,
            includePermissions,
        );
        const cached = await this.cacheService.get<RoleCacheDto>(cacheKey);
        if (cached) {
            return this.toDomainFromCache(cached);
        }

        const roleRecord = includePermissions
            ? await this.findRoleRecordByNameWithPermissions(normalizedName)
            : await this.findRoleRecordByNameLean(normalizedName);

        if (!roleRecord) {
            return null;
        }

        const roleCacheDto = this.toCacheDto(roleRecord);
        await Promise.all([
            this.cacheService.set(cacheKey, roleCacheDto, this.roleCacheTtlSec),
            this.cacheService.set(
                this.getRoleByIdKey(roleRecord.id, includePermissions),
                roleCacheDto,
                this.roleCacheTtlSec,
            ),
        ]);

        return this.toDomain(roleRecord);
    }

    async findAll(): Promise<Role[]> {
        const cached = await this.cacheService.get<RoleCacheDto[]>(
            this.roleListKey,
        );
        if (cached) {
            return cached.map((role) => this.toDomainFromCache(role));
        }

        const roleRecords = await this.prisma.role.findMany({
            include: { permissions: { include: { permission: true } } },
        });

        await this.cacheService.set(
            this.roleListKey,
            roleRecords.map((record) => this.toCacheDto(record)),
            this.roleCacheTtlSec,
        );

        return roleRecords.map((record) => this.toDomain(record));
    }

    async findAllEditable(): Promise<Role[]> {
        const cached = await this.cacheService.get<RoleCacheDto[]>(
            this.roleEditableListKey,
        );
        if (cached) {
            return cached.map((role) => this.toDomainFromCache(role));
        }

        const roleRecords = await this.prisma.role.findMany({
            where: {
                name: {
                    notIn: Role.getProtectedRoleNames(),
                },
            },
            include: { permissions: { include: { permission: true } } },
        });

        await this.cacheService.set(
            this.roleEditableListKey,
            roleRecords.map((record) => this.toCacheDto(record)),
            this.roleCacheTtlSec,
        );

        return roleRecords.map((record) => this.toDomain(record));
    }

    async create(name: string, permissionNames: string[]): Promise<Role> {
        const permissions = await this.resolvePermissions(permissionNames);

        const createdRole = await this.prisma.role.create({
            data: {
                name: name.trim().toLowerCase(),
                permissions: {
                    create: permissions.map((permission) => ({
                        permissionId: permission.id,
                    })),
                },
            },
            include: { permissions: { include: { permission: true } } },
        });

        await this.invalidateRoleCache(createdRole.id, createdRole.name);

        return this.toDomain(createdRole);
    }

    async updatePermissions(
        id: string,
        permissionNames: string[],
    ): Promise<Role> {
        const permissions = await this.resolvePermissions(permissionNames);

        const updatedRole = await this.prisma.$transaction(async (tx) => {
            await tx.rolePermission.deleteMany({ where: { roleId: id } });

            return tx.role.update({
                where: { id },
                data: {
                    permissions: {
                        create: permissions.map((permission) => ({
                            permissionId: permission.id,
                        })),
                    },
                },
                include: { permissions: { include: { permission: true } } },
            });
        });

        await this.invalidateRoleCache(updatedRole.id, updatedRole.name);

        return this.toDomain(updatedRole);
    }

    async delete(id: string): Promise<void> {
        const existingRole = await this.prisma.role.findUnique({
            where: { id },
            select: { name: true },
        });

        await this.prisma.rolePermission.deleteMany({ where: { roleId: id } });
        await this.prisma.role.delete({ where: { id } });

        if (existingRole) {
            await this.invalidateRoleCache(id, existingRole.name);
            return;
        }

        await this.invalidateRoleCache(id);
    }

    private toDomain(roleRecord: RoleRecord): Role {
        const permissions = roleRecord.permissions?.map(
            (entry) => entry.permission.name,
        );

        return Role.create(roleRecord.id, roleRecord.name, permissions);
    }

    private toDomainFromCache(roleRecord: RoleCacheDto): Role {
        return Role.create(
            roleRecord.id,
            roleRecord.name,
            roleRecord.permissions,
        );
    }

    private toCacheDto(roleRecord: RoleRecord): RoleCacheDto {
        return {
            id: roleRecord.id,
            name: roleRecord.name,
            permissions: roleRecord.permissions?.map(
                (entry) => entry.permission.name,
            ),
        };
    }

    private async findRoleRecordByIdLean(
        id: string,
    ): Promise<RoleRecord | null> {
        const role = await this.prisma.role.findUnique({
            where: { id },
            select: {
                id: true,
                name: true,
            },
        });

        if (!role) {
            return null;
        }

        return {
            id: role.id,
            name: role.name,
        };
    }

    private async findRoleRecordByIdWithPermissions(
        id: string,
    ): Promise<RoleRecord | null> {
        const role = await this.prisma.role.findUnique({
            where: { id },
            include: {
                permissions: {
                    include: {
                        permission: {
                            select: {
                                name: true,
                            },
                        },
                    },
                },
            },
        });

        if (!role) {
            return null;
        }

        return {
            id: role.id,
            name: role.name,
            permissions: role.permissions.map((entry) => ({
                permission: {
                    name: entry.permission.name,
                },
            })),
        };
    }

    private async findRoleRecordByNameLean(
        name: string,
    ): Promise<RoleRecord | null> {
        const role = await this.prisma.role.findFirst({
            where: { name },
            select: {
                id: true,
                name: true,
            },
        });

        if (!role) {
            return null;
        }

        return {
            id: role.id,
            name: role.name,
        };
    }

    private async findRoleRecordByNameWithPermissions(
        name: string,
    ): Promise<RoleRecord | null> {
        const role = await this.prisma.role.findFirst({
            where: { name },
            include: {
                permissions: {
                    include: {
                        permission: {
                            select: {
                                name: true,
                            },
                        },
                    },
                },
            },
        });

        if (!role) {
            return null;
        }

        return {
            id: role.id,
            name: role.name,
            permissions: role.permissions.map((entry) => ({
                permission: {
                    name: entry.permission.name,
                },
            })),
        };
    }

    private async invalidateRoleCache(id: string, roleName?: string) {
        const keys = [
            this.getRoleByIdKey(id, true),
            this.getRoleByIdKey(id, false),
            this.roleEditableListKey,
            this.roleListKey,
        ];

        if (roleName) {
            keys.push(this.getRoleByNameKey(roleName, true));
            keys.push(this.getRoleByNameKey(roleName, false));
        }

        await Promise.all(keys.map((key) => this.cacheService.del(key)));
    }

    private getRoleByIdKey(id: string, includePermissions: boolean): string {
        return `${this.roleByIdPrefix}${id}:perm:${includePermissions ? '1' : '0'}`;
    }

    private getRoleByNameKey(
        roleName: string,
        includePermissions: boolean,
    ): string {
        return `${this.roleByNamePrefix}${roleName.trim().toLowerCase()}:perm:${includePermissions ? '1' : '0'}`;
    }

    private async resolvePermissions(permissionNames: string[]) {
        if (!permissionNames.length) {
            return [];
        }

        const normalized = permissionNames.map((permission) =>
            permission.trim().toLowerCase(),
        );

        const permissions = await this.prisma.permission.findMany({
            where: { name: { in: normalized } },
        });

        const foundNames = new Set(
            permissions.map((permission) => permission.name),
        );
        const missingPermissions = normalized.filter(
            (permission) => !foundNames.has(permission),
        );

        if (missingPermissions.length) {
            throw new NotFoundException(
                `Permissions not found: ${missingPermissions.join(', ')}`,
            );
        }

        return permissions;
    }
}
