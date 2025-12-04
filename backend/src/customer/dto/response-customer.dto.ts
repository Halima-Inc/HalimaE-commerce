import { ApiProperty, ApiPropertyOptional, OmitType } from "@nestjs/swagger";
import { CreateCustomerDto } from "./create-cusotmer.dto";

// Response DTO excludes sensitive fields like password, provider, providerId
export class ResponseCustomerDto extends OmitType(CreateCustomerDto, ['password', 'provider', 'providerId'] as const) {
    @ApiProperty({
        description: 'Customer ID',
        example: '123e4567-e89b-12d3-a456-426614174000'
    })
    readonly id: string;

    @ApiProperty({
        description: 'Customer creation date',
        example: '2024-01-01T00:00:00.000Z'
    })
    readonly createdAt: Date;

    @ApiProperty({
        description: 'Customer last update date',
        example: '2024-01-01T00:00:00.000Z'
    })
    readonly updatedAt: Date;
}

// Extended response DTO for admin view with purchase statistics
export class ResponseCustomerWithStatsDto extends ResponseCustomerDto {
    @ApiPropertyOptional({
        description: 'Total amount spent by customer',
        example: 1500.00
    })
    readonly totalSpent?: number;

    @ApiPropertyOptional({
        description: 'Total number of orders placed',
        example: 5
    })
    readonly orderCount?: number;
}

export class ResponseCustomerFilteredDto {
    @ApiProperty({
        description: 'List of customers with optional purchase stats',
        type: [ResponseCustomerWithStatsDto]
    })
    readonly data: ResponseCustomerWithStatsDto[];

    @ApiProperty({
        description: 'Pagination metadata',
        example: { total: 100, totalPages: 10 }
    })
    readonly meta: {
        total: number;
        totalPages: number;
    };
}
