import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type {
    IUserProfileRepository,
    SortOrder,
    UpdateUserProfileInput,
    UserSortField,
} from '../../domain';
import { USER_PROFILE_REPOSITORY } from '../../user.tokens';

@Injectable()
export class CustomerProfileHandler {
    constructor(
        @Inject(USER_PROFILE_REPOSITORY)
        private readonly profileRepository: IUserProfileRepository,
    ) {}

    async getProfile(userId: string) {
        const profile = await this.profileRepository.findById(userId);

        if (!profile) {
            throw new NotFoundException('User profile not found');
        }

        return profile;
    }

    async updateProfile(userId: string, updateDto: UpdateUserProfileInput) {
        return this.profileRepository.update(userId, updateDto);
    }

    async getAllUsers(
        page = 1,
        limit = 10,
        search = '',
        sort: UserSortField = 'name',
        order: SortOrder = 'asc',
    ) {
        return this.profileRepository.findAll(page, limit, search, sort, order);
    }
}
