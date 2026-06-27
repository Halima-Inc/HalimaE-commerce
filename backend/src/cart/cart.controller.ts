import {
    Controller,
    Get,
    Post,
    Patch,
    Delete,
    Body,
    Param,
    Query,
    UseGuards,
    HttpCode,
    HttpStatus,
} from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiBearerAuth,
    ApiExtraModels,
} from '@nestjs/swagger';
import {
    ApiStandardResponse,
    ApiStandardErrorResponse,
    ApiStandardNoContentResponse,
} from '../common/swagger/api-response.decorator';
import { CartService } from './cart.service';
import { LogService } from '../common/log.service';
import {
    AddToCartDto,
    UpdateCartItemDto,
    CartResponseDto,
    CheckoutCartDto,
    AddToCartResponseDto,
} from './dto';
import { CurrentUser, JwtAccessTokenGuard } from '../auth/presentation';

type AuthenticatedUser = {
    userId: string;
    email: string;
};

@ApiTags('cart')
@ApiExtraModels(
    AddToCartDto,
    UpdateCartItemDto,
    CartResponseDto,
    CheckoutCartDto,
    AddToCartResponseDto,
)
@Controller('cart')
@ApiBearerAuth()
@UseGuards(JwtAccessTokenGuard)
export class CartController {
    constructor(
        private readonly cartService: CartService,
        private readonly logger: LogService,
    ) {}

    @Get()
    @ApiOperation({
        summary: 'Get cart',
        description:
            "Retrieve the current customer's shopping cart with all items and details",
    })
    @ApiStandardResponse(CartResponseDto, 'Cart retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart not found',
        'No cart exists for this customer',
    )
    async getCart(
        @CurrentUser() user: AuthenticatedUser,
    ): Promise<CartResponseDto> {
        this.logger.debug(
            `Cart GET request from user: ${user.userId} (${user.email})`,
            'CartController',
        );

        const result = await this.cartService.getCart(user.userId);

        this.logger.debug(
            `Cart GET response for user ${user.userId}: ${result ? 'cart data' : 'null'}`,
            'CartController',
        );

        return result;
    }

    @Get('checkout')
    @ApiOperation({
        summary: 'Get cart for checkout',
        description:
            'Retrieve a lightweight version of the cart with only essential data needed for checkout',
    })
    @ApiStandardResponse(
        CheckoutCartDto,
        'Checkout cart retrieved successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart not found',
        'No cart exists for this customer',
    )
    async getCartForCheckout(
        @CurrentUser() user: AuthenticatedUser,
    ): Promise<CheckoutCartDto | null> {
        return this.cartService.getCartForCheckout(user.userId);
    }

    @Get('count')
    @ApiOperation({
        summary: 'Get cart items count',
        description:
            'Get the total number of items in the cart (useful for header badge)',
    })
    @ApiStandardResponse(Object, 'Cart count retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    async getCartItemsCount(
        @CurrentUser() user: AuthenticatedUser,
    ): Promise<{ count: number }> {
        const count = await this.cartService.getCartItemsCount(user.userId);
        return { count };
    }

    // Calculate cart total
    @Get('total')
    @ApiOperation({
        summary: 'Get cart total',
        description:
            'Calculate the total price of all items in the cart for a specific currency',
    })
    @ApiStandardResponse(Object, 'Cart total calculated successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart not found',
        'No cart exists for this customer',
    )
    async getCartTotal(
        @CurrentUser() user: AuthenticatedUser,
        @Query('currency') currency: string = 'EGP',
    ) {
        return this.cartService.calculateCartTotal(user.userId, currency);
    }

    @Post('items')
    @ApiOperation({
        summary: 'Add item to cart',
        description:
            'Add a product variant to the shopping cart with specified quantity',
    })
    @ApiStandardResponse(
        AddToCartResponseDto,
        'Item added to cart successfully',
        201,
    )
    @ApiStandardErrorResponse(
        400,
        'Invalid request',
        'Invalid variant ID or quantity',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Variant not found',
        'Product variant does not exist',
    )
    @HttpCode(HttpStatus.CREATED)
    async addToCart(
        @CurrentUser() user: AuthenticatedUser,
        @Body() addToCartDto: AddToCartDto,
    ) {
        return this.cartService.addToCart(user.userId, addToCartDto);
    }

    @Patch('items/:itemId')
    @ApiOperation({
        summary: 'Update cart item',
        description: 'Update the quantity of a cart item (set to 0 to remove)',
    })
    @ApiStandardResponse(AddToCartResponseDto, 'Cart item updated successfully')
    @ApiStandardErrorResponse(
        400,
        'Invalid quantity',
        'Quantity must be a positive integer or 0 to remove',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart item not found',
        'Cart item with the given ID was not found',
    )
    async updateCartItem(
        @CurrentUser() user: AuthenticatedUser,
        @Param('itemId') itemId: string,
        @Body() updateCartItemDto: UpdateCartItemDto,
    ) {
        return this.cartService.updateCartItem(
            user.userId,
            itemId,
            updateCartItemDto,
        );
    }

    @Delete('items/:itemId')
    @ApiOperation({
        summary: 'Remove item from cart',
        description: 'Remove a specific item from the shopping cart',
    })
    @ApiStandardNoContentResponse('Cart item removed successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart item not found',
        'Cart item with the given ID was not found',
    )
    @HttpCode(HttpStatus.NO_CONTENT)
    async removeFromCart(
        @CurrentUser() user: AuthenticatedUser,
        @Param('itemId') itemId: string,
    ) {
        return this.cartService.removeFromCart(user.userId, itemId);
    }

    @Delete()
    @ApiOperation({
        summary: 'Clear cart',
        description: 'Remove all items from the shopping cart',
    })
    @ApiStandardNoContentResponse('Cart cleared successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        404,
        'Cart not found',
        'No cart exists for this customer',
    )
    @HttpCode(HttpStatus.NO_CONTENT)
    async clearCart(@CurrentUser() user: AuthenticatedUser) {
        return this.cartService.clearCart(user.userId);
    }
}
