import { Controller, Post, Body, Headers, Param, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiParam, ApiHeader, ApiExtraModels } from '@nestjs/swagger';
import { PaymentService } from './payment.service';
import { LogService } from '../logger/log.service';
import { JwtUserGuard } from '../auth/user-auth/guards';
import { RecordCashPaymentDto, WebhookResponseDto, CashPaymentResponseDto } from './dto';
import { ApiStandardResponse, ApiStandardErrorResponse } from '../../common/swagger/api-response.decorator';

@ApiTags('payment')
@ApiExtraModels(RecordCashPaymentDto, WebhookResponseDto, CashPaymentResponseDto)
@Controller('payment')
export class PaymentController {
    constructor(
        private readonly paymentService: PaymentService,
        private readonly logger: LogService
    ) {}

    @Post('webhook')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ 
        summary: 'Paymob payment webhook',
        description: 'Receives payment status updates from Paymob payment provider. Updates order payment status based on transaction outcome.'
    })
    @ApiHeader({
        name: 'x-paymob-signature',
        description: 'Paymob webhook HMAC-SHA512 signature for verification',
        required: false,
        schema: { type: 'string' }
    })
    @ApiStandardResponse(WebhookResponseDto, 'Webhook processed successfully')
    @ApiStandardErrorResponse(400, 'Bad Request', 'Invalid webhook payload or signature')
    @ApiStandardErrorResponse(500, 'Internal Server Error', 'Failed to process webhook')
    async handleWebhook(
        @Body() payload: any,
        @Headers('x-paymob-signature') signature: string,
        @Headers() headers: any
    ): Promise<{ message: string; }> {
        try {
            this.logger.log(
                'Webhook received from payment provider',
                PaymentController.name
            );

            await this.paymentService.handleWebhook(payload, signature, headers);

            return {
                message: 'Webhook processed successfully'
            };
        } catch (error) {
            this.logger.error(
                'Failed to process webhook',
                error.stack,
                'PaymentController'
            );
            
            throw error;
        }
    }

    @Post('cash/:orderId')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtUserGuard)
    @ApiBearerAuth()
    @ApiOperation({ 
        summary: 'Record cash on delivery payment (Admin/Employee)',
        description: 'Records a cash payment for an order. Used by admin or courier when cash is received upon delivery.'
    })
    @ApiParam({ 
        name: 'orderId', 
        description: 'Order ID for which payment is being recorded',
        example: '123e4567-e89b-12d3-a456-426614174000'
    })
    @ApiStandardResponse(CashPaymentResponseDto, 'Cash payment recorded successfully')
    @ApiStandardErrorResponse(400, 'Bad Request', 'Invalid payment amount or currency')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    @ApiStandardErrorResponse(500, 'Internal Server Error', 'Failed to record payment')
    async recordCashPayment(
        @Param('orderId') orderId: string,
        @Body() body: RecordCashPaymentDto
    ) {
        try {
            this.logger.log(
                `Recording cash payment for order ${orderId}`,
                PaymentController.name
            );

            await this.paymentService.recordCashPayment(
                orderId,
                body.amount,
                body.currency
            );

            return {
                success: true,
                message: 'Cash payment recorded successfully'
            };
        } catch (error) {
            this.logger.error(
                `Failed to record cash payment for order ${orderId}`,
                error.stack,
                PaymentController.name
            );
            throw error;
        }
    }
}
