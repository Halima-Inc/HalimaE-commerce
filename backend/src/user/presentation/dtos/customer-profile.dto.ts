import {
    IsEmail,
    IsIn,
    IsInt,
    IsOptional,
    IsString,
    Length,
    Min,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class UpdateCustomerProfileDto {
    @ApiPropertyOptional({
        description: 'User full name',
        example: 'John Doe',
        minLength: 3,
        maxLength: 255,
    })
    @IsOptional()
    @IsString()
    @Length(3, 255)
    readonly name?: string;

    @ApiPropertyOptional({
        description: 'User email address',
        example: 'john.doe@example.com',
        minLength: 3,
        maxLength: 255,
    })
    @IsOptional()
    @IsString()
    @IsEmail()
    @Length(3, 255)
    readonly email?: string;

    @ApiPropertyOptional({
        description: 'User phone number',
        example: '+1234567890',
        minLength: 8,
        maxLength: 16,
    })
    @IsOptional()
    @IsString()
    @Length(8, 16)
    readonly phone?: string;
}

export class ResponseCustomerDto {
    @ApiProperty({
        description: 'User ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly id!: string;

    @ApiProperty({
        description: 'User full name',
        example: 'John Doe',
    })
    readonly name!: string;

    @ApiProperty({
        description: 'User email',
        example: 'john.doe@example.com',
    })
    readonly email!: string;

    @ApiPropertyOptional({
        description: 'User phone number',
        example: '+1234567890',
    })
    readonly phone?: string;

    @ApiPropertyOptional({
        description: 'User creation timestamp',
        example: '2024-01-01T00:00:00.000Z',
    })
    readonly createdAt?: Date;
}

export class ResponseCustomerWithStatsDto extends ResponseCustomerDto {
    @ApiPropertyOptional({
        description: 'Total amount spent by customer',
        example: 1500.0,
    })
    readonly totalSpent?: number;

    @ApiPropertyOptional({
        description: 'Total number of orders placed',
        example: 5,
    })
    readonly orderCount?: number;
}

export class ResponseCustomerFilteredDto {
    @ApiProperty({
        description: 'List of customers with optional purchase stats',
        type: [ResponseCustomerWithStatsDto],
    })
    readonly data!: ResponseCustomerWithStatsDto[];

    @ApiProperty({
        description: 'Pagination metadata',
        example: { total: 100, totalPages: 10 },
    })
    readonly meta!: {
        total: number;
        totalPages: number;
    };
}

export class FilterCustomerDto {
    @ApiPropertyOptional({
        description: 'Page number for pagination',
        example: 1,
        default: 1,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    page?: number = 1;

    @ApiPropertyOptional({
        description: 'Number of items per page',
        example: 10,
        default: 10,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    limit?: number = 10;

    @ApiPropertyOptional({
        description: 'Search term for filtering by name or email',
        example: 'john',
    })
    @IsOptional()
    @IsString()
    search?: string;

    @ApiPropertyOptional({
        description: 'Sort field',
        example: 'name',
        enum: ['name', 'email', 'createdAt', 'totalSpent', 'orderCount'],
        default: 'name',
    })
    @IsOptional()
    @IsString()
    @IsIn(['name', 'email', 'createdAt', 'totalSpent', 'orderCount'])
    sort?: 'name' | 'email' | 'createdAt' | 'totalSpent' | 'orderCount' =
        'name';

    @ApiPropertyOptional({
        description: 'Sort order',
        example: 'asc',
        enum: ['asc', 'desc'],
        default: 'asc',
    })
    @IsOptional()
    @IsString()
    @IsIn(['asc', 'desc'])
    order?: 'asc' | 'desc' = 'asc';
}
