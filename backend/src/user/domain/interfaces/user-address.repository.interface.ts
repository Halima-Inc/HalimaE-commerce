import {
    CreateUserAddressInput,
    UpdateUserAddressInput,
    UserAddressView,
} from '../types/user.types';

export interface IUserAddressRepository {
    findById(userId: string, addressId: string): Promise<UserAddressView>;
    findAll(userId: string): Promise<UserAddressView[]>;
    create(
        userId: string,
        data: CreateUserAddressInput,
    ): Promise<UserAddressView>;
    update(
        userId: string,
        addressId: string,
        data: UpdateUserAddressInput,
    ): Promise<UserAddressView>;
}
