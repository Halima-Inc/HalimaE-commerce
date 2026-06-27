import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
    DeleteObjectCommand,
    PutObjectCommand,
    S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import {
    IStorageService,
    SignedUploadUrlInput,
} from '../../application/services';

@Injectable()
export class S3StorageService implements IStorageService {
    private readonly client: S3Client;
    private readonly region: string;
    private readonly bucket: string;
    private readonly expiresIn: number;
    private readonly publicBaseUrl?: string;

    constructor(private readonly configService: ConfigService) {
        this.region = this.requireConfig('AWS_S3_REGION');
        this.bucket = this.requireConfig('AWS_S3_BUCKET');

        const endpoint = this.configService.get<string>('AWS_S3_ENDPOINT');
        this.publicBaseUrl = this.configService.get<string>(
            'AWS_S3_PUBLIC_BASE_URL',
        );
        this.expiresIn = this.getExpiresIn();

        this.client = new S3Client({
            region: this.region,
            endpoint,
            forcePathStyle: Boolean(endpoint),
        });
    }

    async createSignedUploadUrl(input: SignedUploadUrlInput): Promise<{
        uploadUrl: string;
        expiresIn: number;
    }> {
        const command = new PutObjectCommand({
            Bucket: this.bucket,
            Key: input.key,
            ContentType: input.contentType,
        });

        const uploadUrl = await getSignedUrl(this.client, command, {
            expiresIn: this.expiresIn,
        });

        return {
            uploadUrl,
            expiresIn: this.expiresIn,
        };
    }

    async deleteObject(key: string): Promise<void> {
        await this.client.send(
            new DeleteObjectCommand({
                Bucket: this.bucket,
                Key: key,
            }),
        );
    }

    buildPublicUrl(key: string): string {
        const normalizedKey = key.replace(/^\/+/, '');

        if (this.publicBaseUrl) {
            return `${this.publicBaseUrl.replace(/\/$/, '')}/${normalizedKey}`;
        }

        return `https://${this.bucket}.s3.${this.region}.amazonaws.com/${encodeURI(normalizedKey)}`;
    }

    private requireConfig(name: string): string {
        const value = this.configService.get<string>(name);
        if (!value) {
            throw new InternalServerErrorException(
                `Missing required configuration: ${name}`,
            );
        }

        return value;
    }

    private getExpiresIn(): number {
        const raw = this.configService.get<string>(
            'AWS_S3_UPLOAD_URL_EXPIRES_IN',
        );
        const parsed = raw ? Number(raw) : 900;

        if (!Number.isFinite(parsed) || parsed <= 0) {
            return 900;
        }

        return Math.floor(parsed);
    }
}
