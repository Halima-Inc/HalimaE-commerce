import { DomainException } from '../../../common/exceptions';

export class InvalidCredentialsException extends DomainException {
    constructor(message: string = 'Invalid credentials provided') {
        super('INVALID_CREDENTIALS', 401, message);
    }
}

export class UserAlreadyExistsException extends DomainException {
    constructor(message: string = 'User already exists with this email') {
        super('USER_ALREADY_EXISTS', 409, message);
    }
}

export class UserNotFoundException extends DomainException {
    constructor(message: string = 'User not found') {
        super('USER_NOT_FOUND', 404, message);
    }
}

export class InvalidTokenException extends DomainException {
    constructor(message: string = 'Invalid or expired token') {
        super('INVALID_TOKEN', 401, message);
    }
}

export class RoleNotFoundException extends DomainException {
    constructor(message: string = 'Role not found') {
        super('ROLE_NOT_FOUND', 404, message);
    }
}

export class UnauthorizedException extends DomainException {
    constructor(message: string = 'Unauthorized access') {
        super('UNAUTHORIZED', 401, message);
    }
}

export class PasswordResetTokenExpiredException extends DomainException {
    constructor(message: string = 'Password reset token has expired') {
        super('PASSWORD_RESET_TOKEN_EXPIRED', 410, message);
    }
}

export class RoleAlreadyExistsException extends DomainException {
    constructor(message: string = 'Role already exists') {
        super('ROLE_ALREADY_EXISTS', 409, message);
    }
}

export class ProtectedRoleException extends DomainException {
    constructor(
        message: string = 'This role is protected and cannot be changed',
    ) {
        super('PROTECTED_ROLE', 403, message);
    }
}

export class PermissionDeniedException extends DomainException {
    constructor(message: string = 'Insufficient permissions') {
        super('PERMISSION_DENIED', 403, message);
    }
}
