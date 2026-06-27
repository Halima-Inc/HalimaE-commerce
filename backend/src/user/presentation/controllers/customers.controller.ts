import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Param,
    Patch,
    Post,
    Query,
    UseGuards,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiExtraModels,
    ApiOperation,
    ApiTags,
} from '@nestjs/swagger';
import {
    ApiStandardErrorResponse,
    ApiStandardResponse,
} from '../../../common/swagger/api-response.decorator';
import {
    CurrentUser,
    JwtAccessTokenGuard,
    RequiredRoles,
    RolesGuard,
} from '../../../auth/presentation';
import {
    CustomerAddressHandler,
    CustomerProfileHandler,
} from '../../application';
import {
    CreateAddressDto,
    FilterCustomerDto,
    ResponseAddressDto,
    ResponseCustomerDto,
    ResponseCustomerFilteredDto,
    UpdateAddressDto,
    UpdateCustomerProfileDto,
} from '../dtos';

type AuthenticatedUser = {
    userId: string;
    email: string;
};

@ApiTags('customers')
@ApiExtraModels(
    UpdateCustomerProfileDto,
    ResponseCustomerDto,
    FilterCustomerDto,
    ResponseCustomerFilteredDto,
    CreateAddressDto,
    UpdateAddressDto,
    ResponseAddressDto,
)
@Controller('customers')
export class CustomersController {
    constructor(
        private readonly customerProfileHandler: CustomerProfileHandler,
        private readonly customerAddressHandler: CustomerAddressHandler,
    ) {}

    @UseGuards(JwtAccessTokenGuard)
    @Get('me')
    @ApiOperation({
        summary: 'Get customer profile',
        description:
            "Retrieve the authenticated customer's profile information",
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseCustomerDto, 'Profile retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'User not found',
        'User profile does not exist',
    )
    @HttpCode(HttpStatus.OK)
    async getProfile(@CurrentUser() user: AuthenticatedUser) {
        return this.customerProfileHandler.getProfile(user.userId);
    }

    @UseGuards(JwtAccessTokenGuard)
    @Patch('me')
    @ApiOperation({
        summary: 'Update customer profile',
        description: "Update the authenticated customer's profile information",
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseCustomerDto, 'Profile updated successfully')
    @ApiStandardErrorResponse(
        400,
        'Invalid update data',
        'Validation failed for profile update',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'User not found',
        'User profile does not exist',
    )
    @HttpCode(HttpStatus.OK)
    async updateProfile(
        @CurrentUser() user: AuthenticatedUser,
        @Body() dto: UpdateCustomerProfileDto,
    ) {
        return this.customerProfileHandler.updateProfile(user.userId, dto);
    }

    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @Get('admin/all')
    @ApiOperation({
        summary: 'Get all customers (Admin)',
        description:
            'Retrieve a paginated list of all customers. Supports sorting by name, email, createdAt, totalSpent (most paying customers), or orderCount (most frequent buyers). Requires admin or employee authentication.',
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(
        ResponseCustomerFilteredDto,
        'Customers retrieved successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @HttpCode(HttpStatus.OK)
    async getAllCustomers(@Query() filters: FilterCustomerDto) {
        return this.customerProfileHandler.getAllUsers(
            filters.page,
            filters.limit,
            filters.search,
            filters.sort,
            filters.order,
        );
    }

    @UseGuards(JwtAccessTokenGuard)
    @Post('addresses')
    @ApiOperation({
        summary: 'Create customer address',
        description:
            "Add a new address to the authenticated customer's account",
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(
        ResponseAddressDto,
        'Address created successfully',
        201,
    )
    @ApiStandardErrorResponse(
        400,
        'Invalid address data',
        'Validation failed for address creation',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @HttpCode(HttpStatus.CREATED)
    async createCustomerAddress(
        @CurrentUser() user: AuthenticatedUser,
        @Body() dto: CreateAddressDto,
    ) {
        return this.customerAddressHandler.createAddress(user.userId, dto);
    }

    @UseGuards(JwtAccessTokenGuard)
    @Get('addresses/:id')
    @ApiOperation({
        summary: 'Get customer address',
        description:
            'Retrieve a specific address of the authenticated customer',
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Address retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Address not found',
        'Address with the given ID was not found',
    )
    @HttpCode(HttpStatus.OK)
    async getCustomerAddress(
        @CurrentUser() user: AuthenticatedUser,
        @Param('id') id: string,
    ) {
        return this.customerAddressHandler.getAddress(user.userId, id);
    }

    /// TODO: make Paginate customer addresses endpoint and test it in e2e tests.
    @UseGuards(JwtAccessTokenGuard)
    @Get('addresses')
    @ApiOperation({
        summary: 'Get all customer addresses',
        description: 'Retrieve all addresses of the authenticated customer',
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Addresses retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @HttpCode(HttpStatus.OK)
    async getCustomerAddresses(@CurrentUser() user: AuthenticatedUser) {
        return this.customerAddressHandler.getAddresses(user.userId);
    }

    @UseGuards(JwtAccessTokenGuard)
    @Patch('addresses/:id')
    @ApiOperation({
        summary: 'Update customer address',
        description: 'Update a specific address of the authenticated customer',
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Address updated successfully')
    @ApiStandardErrorResponse(
        400,
        'Invalid address data',
        'Validation failed for address update',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Address not found',
        'Address with the given ID was not found',
    )
    @HttpCode(HttpStatus.OK)
    async updateCustomerAddress(
        @CurrentUser() user: AuthenticatedUser,
        @Param('id') id: string,
        @Body() dto: UpdateAddressDto,
    ) {
        return this.customerAddressHandler.updateAddress(user.userId, id, dto);
    }
}
