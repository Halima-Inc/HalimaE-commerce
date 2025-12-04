import {
    Controller,
    Get,
    UseGuards,
    Request,
    Body,
    Patch,
    Query,
    HttpCode,
    HttpStatus,
    Post,
    Param
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiExtraModels } from '@nestjs/swagger';
import { ApiStandardResponse, ApiStandardErrorResponse } from '../../common/swagger/api-response.decorator';
import { CustomerService } from './customer.service';
import { JwtCustomerGuard } from '../auth/customer-auth/guards/jwt.customer.guard';
import { JwtUserGuard, RolesGuard } from '../auth/user-auth/guards';
import { Roles } from '../auth/user-auth/decorators';
import {
    CreateAddressDto,
    UpdateCustomerDto,
    CreateCustomerDto,
    UpdateAddressDto,
    ResponseCustomerDto,
    ResponseAddressDto,
    FilterCustomerDto,
    ResponseCustomerFilteredDto,
    ResponseCustomerWithStatsDto
} from './dto';
import { AddressService } from './address.service';
import type { RequestWithCustomer } from '../../common/types/request-with-customer.type';

@ApiTags('customers')
@ApiExtraModels(CreateCustomerDto, UpdateCustomerDto, CreateAddressDto, UpdateAddressDto, ResponseCustomerDto, ResponseAddressDto, FilterCustomerDto, ResponseCustomerFilteredDto, ResponseCustomerWithStatsDto)
@Controller('customers')
export class CustomerController {
    constructor(
        private readonly customerService: CustomerService,
        private readonly addressService: AddressService,
    ) {}

    @UseGuards(JwtCustomerGuard)
    @Get('me')
    @ApiOperation({ summary: 'Get customer profile', description: 'Retrieve the authenticated customer\'s profile information' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseCustomerDto, 'Profile retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Customer not found', 'Customer profile does not exist')
    @HttpCode(HttpStatus.OK)
    async getProfile(@Request() req: RequestWithCustomer) {
        // The 'customer' object is attached to the request by the JwtCustomerGuard
        return this.customerService.findById(req.customer.sub);
    }

    @UseGuards(JwtCustomerGuard)
    @Patch('me')
    @ApiOperation({ summary: 'Update customer profile', description: 'Update the authenticated customer\'s profile information' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseCustomerDto, 'Profile updated successfully')
    @ApiStandardErrorResponse(400, 'Invalid update data', 'Validation failed for profile update')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Customer not found', 'Customer profile does not exist')
    @HttpCode(HttpStatus.OK)
    async updateProfile(@Request() req: RequestWithCustomer, @Body() dto: UpdateCustomerDto) {
        return this.customerService.update(req.customer.sub, dto);
    }

    // Admin-only routes

    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @Get('admin/all')
    @ApiOperation({ 
        summary: 'Get all customers (Admin)', 
        description: 'Retrieve a paginated list of all customers. Supports sorting by name, email, createdAt, totalSpent (most paying customers), or orderCount (most frequent buyers). Requires admin or employee authentication.' 
    })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseCustomerFilteredDto, 'Customers retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @HttpCode(HttpStatus.OK)
    async getAllCustomers(@Query() filters: FilterCustomerDto) {
        return this.customerService.findAll(
            filters.page,
            filters.limit,
            filters.search,
            filters.sort,
            filters.order,
        );
    }

    // Customer address routes

    @UseGuards(JwtCustomerGuard)
    @Post('addresses')
    @ApiOperation({ summary: 'Create customer address', description: 'Add a new address to the authenticated customer\'s account' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Address created successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid address data', 'Validation failed for address creation')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @HttpCode(HttpStatus.CREATED)
    async createCustomerAddress(@Request() req: RequestWithCustomer, @Body() dto: CreateAddressDto) {
        return this.addressService.create(req.customer.sub, dto);
    }

    @UseGuards(JwtCustomerGuard)
    @Get('addresses/:id')
    @ApiOperation({ summary: 'Get customer address', description: 'Retrieve a specific address of the authenticated customer' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Address retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Address not found', 'Address with the given ID was not found')
    @HttpCode(HttpStatus.OK)
    async getCustomerAddress(@Request() req: RequestWithCustomer, @Param('id') id: string) {
        return this.addressService.findById(req.customer.sub, id);
    }


    @UseGuards(JwtCustomerGuard)
    @Get('addresses')
    @ApiOperation({ summary: 'Get all customer addresses', description: 'Retrieve all addresses of the authenticated customer' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Addresses retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @HttpCode(HttpStatus.OK)
    async getCustomerAddresses(@Request() req: RequestWithCustomer) {
        return this.addressService.findAll(req.customer.sub);
    }

    @UseGuards(JwtCustomerGuard)
    @Patch('addresses/:id')
    @ApiOperation({ summary: 'Update customer address', description: 'Update a specific address of the authenticated customer' })
    @ApiBearerAuth('JWT-auth')
    @ApiStandardResponse(ResponseAddressDto, 'Address updated successfully')
    @ApiStandardErrorResponse(400, 'Invalid address data', 'Validation failed for address update')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Address not found', 'Address with the given ID was not found')
    @HttpCode(HttpStatus.OK)
    async updateCustomerAddress(@Request() req: RequestWithCustomer, @Param('id') id: string, @Body() dto: CreateAddressDto) {
        return this.addressService.update(req.customer.sub, id, dto);
    }
}
