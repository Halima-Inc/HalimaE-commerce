import { Module } from '@nestjs/common';
import { CartService } from './cart.service';
import { CartController } from './cart.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
    imports: [AuthModule],
    controllers: [CartController],
    providers: [CartService],
    exports: [CartService], // Export service for use in other modules (like orders)
})
export class CartModule {}
