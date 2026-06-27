import { Injectable, LoggerService, LogLevel } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import 'winston-daily-rotate-file';
import DatadogWinston from 'datadog-winston';
import { inspect } from 'util';

@Injectable()
export class LogService implements LoggerService {
    private readonly _logger: winston.Logger;

    constructor(private readonly configService: ConfigService) {
        const transports = this.createTransports();
        const logLevel = this.configService.get<string>('LOG_LEVEL', 'info');

        this._logger = winston.createLogger({
            level: logLevel,
            transports,
        });
    }

    private createTransports() {
        const isProduction =
            this.configService.get('NODE_ENV') === 'production';
        const transports: winston.transport[] = [];

        if (isProduction) {
            transports.push(this.createDailyRotateFileTransport());

            const datadogApiKey =
                this.configService.get<string>('DATADOG_API_KEY');
            if (datadogApiKey) {
                transports.push(this.createDatadogTransport(datadogApiKey));
            }
        } else {
            transports.push(this.createConsoleTransport());
        }

        return transports;
    }

    private createConsoleTransport() {
        const nestLikeFormat = winston.format.printf(
            ({ level, message, context, timestamp, ...meta }) => {
                const pid = process.pid;
                const formattedTimestamp = new Date(
                    timestamp as string | number | Date,
                ).toLocaleString();
                const contextMessage = context
                    ? `[${String(context as any)}] `
                    : '';

                const formattedMeta =
                    meta && Object.keys(meta).length
                        ? `\n${inspect(meta, { colors: true, depth: null })}`
                        : '';

                return `[Nest] ${pid} - ${formattedTimestamp}\t${level} ${contextMessage}${String(message)}${formattedMeta}`;
            },
        );

        return new winston.transports.Console({
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.colorize({ all: true }),
                nestLikeFormat,
            ),
        });
    }

    private createDailyRotateFileTransport() {
        return new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json(),
            ),
        });
    }

    private createDatadogTransport(apiKey: string) {
        return new DatadogWinston({
            apiKey,
            hostname: this.configService.get<string>('HOSTNAME', 'my-app'),
            service: this.configService.get<string>(
                'APP_NAME',
                'halima-ecommerce',
            ),
            ddsource: 'nodejs',
            intakeRegion: this.configService.get<string>(
                'DATADOG_REGION',
                'US',
            ),
        });
    }

    log(message: any, context?: string) {
        this._logger.info(message, { context });
    }

    error(message: any, trace?: string, context?: string) {
        this._logger.error(message, { context, trace });
    }

    warn(message: any, context?: string) {
        this._logger.warn(message, { context });
    }

    debug(message: any, context?: string) {
        this._logger.debug(message, { context });
    }

    verbose(message: any, context?: string) {
        this._logger.verbose(message, { context });
    }

    fatal(message: any, trace?: string, context?: string) {
        this._logger.crit(message, { context, trace });
    }

    setLogLevels(levels: LogLevel[]) {
        const order: LogLevel[] = [
            'fatal',
            'error',
            'warn',
            'log',
            'debug',
            'verbose',
        ];
        const highestLevel = levels
            .map((level) => order.indexOf(level))
            .reduce((max, current) => (current > max ? current : max), -1);

        if (highestLevel !== -1) {
            this._logger.level = order[highestLevel];
        }
    }
}
