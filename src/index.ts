"use strict";

import * as argon2 from "argon2";

export const defaultSaltLength: number = 32;

export class pwhaas {
    static async generateSalt(length: number = defaultSaltLength): Promise<Buffer> {
        return await argon2.generateSalt(length);
    }

    static async hash(plain: string): Promise<string> {
        const hash = await argon2.hash(plain, await pwhaas.generateSalt(32));
        return hash;
    }

    static async verify(hash: string, plain: string): Promise<boolean> {
        return await argon2.verify(hash, plain);
    }
}