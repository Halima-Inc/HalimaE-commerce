import { Injectable, UnauthorizedException } from "@nestjs/common";
import { Strategy, ExtractJwt } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { ConfigService } from "@nestjs/config";
import { CustomerService } from "../../../customer/customer.service";


@Injectable()
export class JwtCustomerStrategy extends PassportStrategy(Strategy, 'jwt-customer') {
    constructor(
        private readonly configService: ConfigService,
        private readonly customerService: CustomerService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.getOrThrow<string>('JWT_CUSTOMER_SECRET'),
        });
    }

    async validate(payload: any) {
        const customer = await this.customerService.findById(payload.sub);
        if (!customer) {
            throw new UnauthorizedException('Customer not found');
        }
        return {sub: customer.id, email: customer.email};
    }
}
