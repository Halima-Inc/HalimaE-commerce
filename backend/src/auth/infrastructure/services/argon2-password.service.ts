import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { IPasswordService } from '../../application/services';

@Injectable()
export class Argon2PasswordService implements IPasswordService {
    async hashPassword(password: string): Promise<string> {
        return argon2.hash(password);
    }

    async comparePassword(password: string, hash: string): Promise<boolean> {
        return argon2.verify(hash, password);
    }
}
