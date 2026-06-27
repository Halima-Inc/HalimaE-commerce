export type UserSortField =
    | 'name'
    | 'email'
    | 'createdAt'
    | 'totalSpent'
    | 'orderCount';

export type SortOrder = 'asc' | 'desc';

export type UserProfileView = {
    id: string;
    name: string;
    email: string;
    phone: string | null;
    createdAt?: Date;
};

export type UserProfileWithStatsView = UserProfileView & {
    totalSpent?: number;
    orderCount?: number;
};

export type UserListResponse = {
    data: UserProfileWithStatsView[];
    meta: {
        total: number;
        totalPages: number;
    };
};

export type UpdateUserProfileInput = {
    name?: string;
    email?: string;
    phone?: string | null;
};

export type UserAddressView = {
    id: string;
    userId: string;
    firstName: string;
    lastName: string;
    phone: string | null;
    line1: string;
    line2: string | null;
    city: string;
    country: string;
    postalCode: string;
    isDefault: boolean;
    createdAt: Date;
    updatedAt: Date;
};

export type CreateUserAddressInput = {
    firstName: string;
    lastName: string;
    phone?: string;
    line1: string;
    line2?: string;
    city: string;
    country: string;
    postalCode: string;
    isDefault: boolean;
};

export type UpdateUserAddressInput = Partial<CreateUserAddressInput>;
