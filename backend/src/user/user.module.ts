import { Module } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthModule } from '../auth/auth.module';
import { CustomerAddressHandler, CustomerProfileHandler } from './application';
import {
    PrismaUserAddressRepository,
    PrismaUserProfileRepository,
} from './infrastructure';
import { CustomersController } from './presentation';
import {
    USER_ADDRESS_REPOSITORY,
    USER_PROFILE_REPOSITORY,
} from './user.tokens';

@Module({
    imports: [AuthModule],
    controllers: [CustomersController],
    providers: [
        CustomerProfileHandler,
        CustomerAddressHandler,
        {
            provide: USER_PROFILE_REPOSITORY,
            useClass: PrismaUserProfileRepository,
        },
        {
            provide: USER_ADDRESS_REPOSITORY,
            useClass: PrismaUserAddressRepository,
        },
        PrismaService,
    ],
})
export class UsersModule {}
