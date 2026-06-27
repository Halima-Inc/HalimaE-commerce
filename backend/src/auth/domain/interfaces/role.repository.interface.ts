import { Role } from '../entities';

export type RoleLookupOptions = {
    includePermissions?: boolean;
};

export interface IRoleRepository {
    findById(id: string, options?: RoleLookupOptions): Promise<Role | null>;
    findByName(name: string, options?: RoleLookupOptions): Promise<Role | null>;
    findAll(): Promise<Role[]>;
    findAllEditable(): Promise<Role[]>;
    create(name: string, permissionNames: string[]): Promise<Role>;
    updatePermissions(id: string, permissionNames: string[]): Promise<Role>;
    delete(id: string): Promise<void>;
}
