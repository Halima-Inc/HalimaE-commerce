import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, Profile } from "passport-google-oauth20";

@Injectable()
export class GoogleCustomerStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(configService: ConfigService) {
        super({
            clientID    : configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
            clientSecret: configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
            callbackURL : configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
            scope       : ['email', 'profile'],
        });
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: Profile,
    ) {
        const { id, emails, displayName } = profile;
        const email = emails && emails.length > 0 ? emails[0].value : null;

        return {
            provider: 'google',
            providerId: id,
            email,
            name: displayName,
            accessToken,
        };
    }
}