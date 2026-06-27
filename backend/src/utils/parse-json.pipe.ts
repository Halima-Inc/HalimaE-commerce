import {
    PipeTransform,
    Injectable,
    ArgumentMetadata,
    BadRequestException,
} from '@nestjs/common';

@Injectable()
export class ParseJsonPipe implements PipeTransform<string, any> {
    transform(value: string, metadata: ArgumentMetadata): any {
        if (value === undefined || value === null) {
            return [];
        }
        try {
            return JSON.parse(value);
        } catch {
            throw new BadRequestException(
                `Validation failed (invalid JSON string) in field: ${metadata.data}`,
            );
        }
    }
}
