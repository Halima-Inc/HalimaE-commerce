import { Inject, Injectable } from '@nestjs/common';
import type {
    CreateUserAddressInput,
    IUserAddressRepository,
    UpdateUserAddressInput,
} from '../../domain';
import { USER_ADDRESS_REPOSITORY } from '../../user.tokens';

@Injectable()
export class CustomerAddressHandler {
    constructor(
        @Inject(USER_ADDRESS_REPOSITORY)
        private readonly addressRepository: IUserAddressRepository,
    ) {}

    async createAddress(userId: string, dto: CreateUserAddressInput) {
        return this.addressRepository.create(userId, dto);
    }

    async getAddress(userId: string, addressId: string) {
        return this.addressRepository.findById(userId, addressId);
    }

    async getAddresses(userId: string) {
        return this.addressRepository.findAll(userId);
    }

    async updateAddress(
        userId: string,
        addressId: string,
        dto: UpdateUserAddressInput,
    ) {
        return this.addressRepository.update(userId, addressId, dto);
    }
}
