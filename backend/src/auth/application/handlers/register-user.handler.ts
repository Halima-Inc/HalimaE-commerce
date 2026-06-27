import { Inject, Injectable } from '@nestjs/common';
import { RegisterUserCommand } from '../commands';
import {
    User,
    Email,
    EncryptedPassword,
    UserAlreadyExistsException,
    RoleNotFoundException,
} from '../../domain';
import type { IUserRepository, IRoleRepository } from '../../domain/interfaces';
import type { IPasswordService } from '../services/password.service.interface';
import {
    PASSWORD_SERVICE,
    ROLE_REPOSITORY,
    USER_REPOSITORY,
} from '../../auth.tokens';
import { randomUUID } from 'crypto';

@Injectable()
export class RegisterUserHandler {
    private static readonly DEFAULT_SIGNUP_ROLE = 'customer';

    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(ROLE_REPOSITORY)
        private readonly roleRepository: IRoleRepository,
        @Inject(PASSWORD_SERVICE)
        private readonly passwordService: IPasswordService,
    ) {}

    async execute(command: RegisterUserCommand): Promise<User> {
        const existingUser = await this.userRepository.findByEmail(
            command.email,
        );
        if (existingUser) {
            throw new UserAlreadyExistsException(
                `Email ${command.email} is already registered`,
            );
        }

        const customerRole = await this.roleRepository.findByName(
            RegisterUserHandler.DEFAULT_SIGNUP_ROLE,
            {
                includePermissions: false,
            },
        );
        if (!customerRole) {
            throw new RoleNotFoundException(
                `Critical role ${RegisterUserHandler.DEFAULT_SIGNUP_ROLE} not found`,
            );
        }
        const roleId = customerRole.getId();

        const hashedPassword = await this.passwordService.hashPassword(
            command.password,
        );

        const userId = randomUUID(); // TODO: Use uuid v7 for relational dbs performance
        const email = Email.create(command.email);
        const encryptedPassword = EncryptedPassword.create(hashedPassword);

        const user = User.create(
            userId,
            email,
            command.name,
            encryptedPassword,
            roleId,
            command.phone,
        );

        await this.userRepository.save(user);

        return user;
    }
}
