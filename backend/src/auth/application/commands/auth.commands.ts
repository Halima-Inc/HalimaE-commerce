export class RegisterUserCommand {
    constructor(
        public readonly email: string,
        public readonly name: string,
        public readonly password: string,
        public readonly roleId?: string,
        public readonly phone?: string,
    ) {}
}

export class LoginUserCommand {
    constructor(
        public readonly email: string,
        public readonly password: string,
    ) {}
}

export class RefreshTokenCommand {
    constructor(
        public readonly refreshToken: string,
        public readonly deviceInfo?: string,
        public readonly ip?: string,
    ) {}
}

export class ResetPasswordCommand {
    constructor(
        public readonly token: string,
        public readonly newPassword: string,
    ) {}
}

export class RequestPasswordResetCommand {
    constructor(public readonly email: string) {}
}

export class ChangePasswordCommand {
    constructor(
        public readonly userId: string,
        public readonly currentPassword: string,
        public readonly newPassword: string,
    ) {}
}
