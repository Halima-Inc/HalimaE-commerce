export abstract class DomainException extends Error {
    constructor(
        public readonly code: string,
        public readonly httpStatus: number,
        message: string,
    ) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
