import {
    IsEmail,
    IsArray,
    IsOptional,
    IsString,
    MaxLength,
    MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterUserRequestDto {
    @IsEmail()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MaxLength(320)
    email!: string;

    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MinLength(2)
    @MaxLength(120)
    name!: string;

    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MinLength(8)
    @MaxLength(128)
    password!: string;

    @IsOptional()
    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MaxLength(32)
    phone?: string;
}

export class LoginUserRequestDto {
    @IsEmail()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MaxLength(320)
    email!: string;

    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MinLength(1)
    @MaxLength(128)
    password!: string;
}

export class RefreshTokenRequestDto {
    @IsString()
    refreshToken!: string;
}

export class ResetPasswordRequestDto {
    @IsString()
    token!: string;

    @IsString()
    @MinLength(8)
    @MaxLength(128)
    newPassword!: string;
}

export class RequestPasswordResetRequestDto {
    @IsEmail()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MaxLength(320)
    email!: string;
}

export class ChangePasswordRequestDto {
    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MinLength(8)
    @MaxLength(128)
    currentPassword!: string;

    @IsString()
    @Transform(({ value }) =>
        typeof value === 'string' ? value.trim() : value,
    )
    @MinLength(8)
    @MaxLength(128)
    newPassword!: string;
}

export class UserResponseDto {
    id!: string;
    email!: string;
    name!: string;
    phone?: string;
    role?: {
        id: string;
        name: string;
    };
}

export class AuthResponseDto {
    accessToken!: string;
    refreshToken!: string;
    user!: UserResponseDto;
}

export class RefreshTokenResponseDto {
    accessToken!: string;
    refreshToken!: string;
}

export class CreateRoleRequestDto {
    @ApiProperty({
        description: 'Role name',
        example: 'support',
        maxLength: 120,
    })
    @IsString()
    @MaxLength(120)
    name!: string;

    @ApiProperty({
        description: 'Permission names assigned to the role',
        example: ['roles.read', 'roles.update'],
        type: [String],
    })
    @IsArray()
    @IsString({ each: true })
    permissions!: string[];
}

export class UpdateRolePermissionsRequestDto {
    @ApiProperty({
        description: 'Permission names assigned to the role',
        example: ['roles.read', 'roles.update'],
        type: [String],
    })
    @IsArray()
    @IsString({ each: true })
    permissions!: string[];
}

export class RoleResponseDto {
    @ApiProperty({
        description: 'Role identifier',
        example: '4f2e9c9f-6a82-4a90-b726-df3b7f4f4f33',
    })
    id!: string;

    @ApiProperty({
        description: 'Role name',
        example: 'support',
    })
    name!: string;

    @ApiProperty({
        description: 'Permission names assigned to the role',
        example: ['roles.read', 'roles.update'],
        type: [String],
        required: false,
    })
    permissions?: string[];
}
