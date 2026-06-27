import {
    SortOrder,
    UpdateUserProfileInput,
    UserListResponse,
    UserProfileView,
    UserSortField,
} from '../types/user.types';

export interface IUserProfileRepository {
    findById(userId: string): Promise<UserProfileView | null>;

    update(
        userId: string,
        data: UpdateUserProfileInput,
    ): Promise<UserProfileView>;

    findAll(
        page: number,
        limit: number,
        search: string,
        sort: UserSortField,
        order: SortOrder,
    ): Promise<UserListResponse>;
}
