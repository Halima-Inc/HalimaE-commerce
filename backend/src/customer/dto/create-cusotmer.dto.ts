import { 
    IsEmail,
    IsEnum,
    IsNotEmpty,
    IsOptional,
    IsString,
    Length,
} from "class-validator";
import { Status } from "@prisma/client";
import { ApiProperty } from "@nestjs/swagger";
import { PROVIDER } from "@prisma/client";

export class CreateCustomerDto {
    @ApiProperty({
        description: 'Customer full name',
        example: 'John Doe',
        minLength: 3,
        maxLength: 255
    })
    @IsString()
    @IsNotEmpty()
    @Length(3, 255)
    readonly name: string;

    @ApiProperty({
        description: 'Customer email address',
        example: 'john.doe@example.com',
        minLength: 3,
        maxLength: 255
    })
    @IsString()
    @IsNotEmpty()
    @IsEmail()
    @Length(3, 255)
    readonly email: string;

    @ApiProperty({
        description: 'Customer password',
        example: 'SecurePass123',
        minLength: 8,
        maxLength: 16
    })
    @IsString()
    @IsNotEmpty()
    @Length(8, 16)
    readonly password: string;

    @ApiProperty({
        description: 'Customer phone number',
        example: '+1234567890',
        required: false,
        minLength: 8,
        maxLength: 16
    })
    @IsOptional()
    @IsString()
    @Length(8, 16)
    readonly phone?: string;

    @ApiProperty({
        description: 'Customer account status',
        enum: Status,
        default: Status.ACTIVE,
        example: Status.ACTIVE
    })
    @IsEnum(Status)
    @IsNotEmpty()
    readonly status: Status = Status.ACTIVE;

    @ApiProperty({
        description: 'OAuth provider name (e.g., google, facebook)',
        example: PROVIDER.GOOGLE,
        required: false
    })
    @IsOptional()
    @IsEnum(PROVIDER)
    readonly provider?: PROVIDER;

    @ApiProperty({
        description: 'OAuth provider user ID',
        example: '1234567890',
        required: false
    })
    @IsOptional()
    @IsString()
    readonly providerId?: string;
}