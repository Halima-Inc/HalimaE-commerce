import { ApiProperty } from '@nestjs/swagger';

export class WebhookResponseDto {
    @ApiProperty({
        description: 'Message indicating webhook processing status',
        example: 'Webhook processed successfully',
    })
    message: string;
}
