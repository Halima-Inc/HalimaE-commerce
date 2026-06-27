import { Inject, Injectable } from '@nestjs/common';
import { ResetPasswordCommand } from '../commands';
import {
    User,
    EncryptedPassword,
    UserNotFoundException,
    PasswordResetTokenExpiredException,
} from '../../domain';
import type {
    IUserRepository,
    IPasswordResetTokenRepository,
} from '../../domain/interfaces';
import type { IPasswordService } from '../services/password.service.interface';
import {
    PASSWORD_RESET_TOKEN_REPOSITORY,
    PASSWORD_SERVICE,
    USER_REPOSITORY,
} from '../../auth.tokens';

@Injectable()
export class ResetPasswordHandler {
    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(PASSWORD_RESET_TOKEN_REPOSITORY)
        private readonly passwordResetTokenRepository: IPasswordResetTokenRepository,
        @Inject(PASSWORD_SERVICE)
        private readonly passwordService: IPasswordService,
    ) {}

    async execute(command: ResetPasswordCommand): Promise<void> {
        const resetToken =
            await this.passwordResetTokenRepository.findByTokenHash(
                command.token,
            );

        if (!resetToken || resetToken.isExpired()) {
            throw new PasswordResetTokenExpiredException();
        }

        const user = await this.userRepository.findById(resetToken.getUserId());
        if (!user) {
            throw new UserNotFoundException('User not found');
        }

        const updatedUser = User.create(
            user.getId(),
            user.getEmail(),
            user.getName(),
            EncryptedPassword.create(
                await this.passwordService.hashPassword(command.newPassword),
            ),
            user.getRoleId(),
            user.getPhone(),
            user.getProvider(),
            user.getProviderId(),
            user.getStatus(),
            user.getCreatedAt(),
            user.getUpdatedAt(),
        );

        await this.userRepository.update(updatedUser);

        await this.passwordResetTokenRepository.delete(resetToken.getId());
    }
}
