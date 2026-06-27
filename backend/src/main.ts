import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { LoggerService, ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';
import helmet from 'helmet';
import { LogService } from './common/log.service';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';

async function bootstrap() {
    const app = await NestFactory.create<NestExpressApplication>(AppModule);
    const configService = app.get(ConfigService);

    app.use(helmet());
    app.enableCors({
        origin:
            configService.get<string>('FRONTEND_URL') ||
            'http://localhost:3001',
        methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
        credentials: true,
        maxAge: 3600,
    });

    app.disable('x-powered-by');

    const logService = app.get<LoggerService>(LogService);
    app.useLogger(logService);

    app.useGlobalFilters(new GlobalExceptionFilter(logService));

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            transform: true,
            transformOptions: { enableImplicitConversion: true },
        }),
    );

    app.useStaticAssets(join(__dirname, '..', 'public', 'uploads'), {
        prefix: '/images/',
    });

    app.setGlobalPrefix('/api');

    app.use(cookieParser(configService.get<string>('COOKIE_SECRET')));

    // Swagger configuration
    const config = new DocumentBuilder()
        .setTitle('Halima E-commerce API')
        .setDescription(
            'Professional e-commerce API documentation for Halima E-commerce platform',
        )
        .setVersion('1.0')
        .addTag('categories', 'Category management endpoints')
        .addTag('products', 'Product management endpoints')
        .addTag('cart', 'Shopping cart endpoints')
        .addTag('customers', 'Customer management endpoints')
        .addTag('customer-auth', 'Customer authentication endpoints')
        .addTag('admin-auth', 'Admin/Employee authentication endpoints')
        .addTag('users', 'User management endpoints')
        .addBearerAuth(
            {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
                name: 'JWT',
                description: 'Enter JWT token',
                in: 'header',
            },
            'JWT-auth',
        )
        .addCookieAuth(
            'refresh_token',
            {
                type: 'apiKey',
                in: 'cookie',
                name: 'refresh_token',
                description:
                    'Refresh token stored as httpOnly cookie. Set automatically on login/signup.',
            },
            'refresh_token',
        )
        .build();

    const document = SwaggerModule.createDocument(app, config);

    SwaggerModule.setup('api/docs', app, document, {
        swaggerOptions: {
            persistAuthorization: true,
            displayRequestDuration: true,
        },
    });

    const port = configService.get<number>('PORT') || 3000;
    await app.listen(port);
}
bootstrap();
