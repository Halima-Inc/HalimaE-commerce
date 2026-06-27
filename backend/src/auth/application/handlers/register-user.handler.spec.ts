import { Test, TestingModule } from '@nestjs/testing';
import { RegisterUserHandler } from './register-user.handler';
import {
    PASSWORD_SERVICE,
    ROLE_REPOSITORY,
    USER_REPOSITORY,
} from '../../auth.tokens';
import { RegisterUserCommand } from '../commands';

describe('RegisterUserHandler', () => {
    let handler: RegisterUserHandler;

    const userRepository = {
        findByEmail: jest.fn(),
        save: jest.fn(),
    };

    const roleRepository = {
        findByName: jest.fn(),
    };

    const passwordService = {
        hashPassword: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RegisterUserHandler,
                {
                    provide: USER_REPOSITORY,
                    useValue: userRepository,
                },
                {
                    provide: ROLE_REPOSITORY,
                    useValue: roleRepository,
                },
                {
                    provide: PASSWORD_SERVICE,
                    useValue: passwordService,
                },
            ],
        }).compile();

        handler = module.get(RegisterUserHandler);

        jest.clearAllMocks();
    });

    it('registers a new user with the default customer role', async () => {
        userRepository.findByEmail.mockResolvedValue(null);
        passwordService.hashPassword.mockResolvedValue('hashed-password');
        roleRepository.findByName.mockResolvedValue({
            getId: () => 'role-customer',
        });

        const result = await handler.execute(
            new RegisterUserCommand(
                'john.doe@example.com',
                'John Doe',
                'Password123!',
            ),
        );

        expect(userRepository.findByEmail).toHaveBeenCalledWith(
            'john.doe@example.com',
        );
        expect(roleRepository.findByName).toHaveBeenCalledWith('customer');
        expect(passwordService.hashPassword).toHaveBeenCalledWith(
            'Password123!',
        );
        expect(userRepository.save).toHaveBeenCalledTimes(1);
        expect(result.getName()).toBe('John Doe');
        expect(result.getRoleId()).toBe('role-customer');
    });
});
