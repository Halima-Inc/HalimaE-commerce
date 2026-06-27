export type SignedUploadUrlInput = {
    key: string;
    contentType: string;
};

export type SignedUploadUrlResult = {
    uploadUrl: string;
    expiresIn: number;
};

export interface IStorageService {
    createSignedUploadUrl(
        input: SignedUploadUrlInput,
    ): Promise<SignedUploadUrlResult>;
    deleteObject(key: string): Promise<void>;
    buildPublicUrl(key: string): string;
}
