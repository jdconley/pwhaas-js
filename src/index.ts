"use strict";

import * as argon2 from "argon2";
import * as rp from "request-promise";

export const defaultSaltLength: number = 32;
export const defaultMaxHashTimeMs: number = 500;
export var defaultClientOptions: any = {};

export interface IPwhaas {
    hash(plain: string, salt: Buffer, maxtime?: number): Promise<IHashResponse>;
    verify(hash: string, plain: string, salt: Buffer): Promise<IVerifyResponse>;
    generateSalt(length: number): Promise<Buffer>;
}

export interface IHashRequest {
    maxtime: number;
    plain: string;
}

export interface IVerifyRequest {
    hash: string;
    plain: string;
}

export interface IHashTiming {
    salt: number;
    hash: number;
}

export interface IVerifyTiming {
    verify: number;
}

export interface IHashResponse {
    local: boolean;
    options: argon2.IOptions;
    hash: string;
    timing: IHashTiming;
}

export interface IVerifyResponse {
    local: boolean;
    match: boolean;
    timing: IVerifyTiming;
}

export class HashRequest implements IHashRequest {
    constructor(public plain: string, public maxtime: number) {}
}

export class VerifyRequest implements IVerifyRequest {
    constructor(public hash: string, public plain: string) {}
}

export class PwhaasClient {
    serviceRootUri = "https://api.pwhaas.com";

    constructor(public options: any) {
    }

    async hash(plain: string, maxtime?: number): Promise<IHashResponse> {
        const req = new HashRequest(plain, maxtime || defaultMaxHashTimeMs);

        return await this.postJson("hash", req);
    }

    async verify(hash: string, plain: string): Promise<IVerifyResponse> {
        const req = new VerifyRequest(hash, plain);

        return await this.postJson("verify", req);
    }

    async generateSalt(length: number): Promise<Buffer> {
        return argon2.generateSalt(length);
    }

    private async postJson(relativeUri: string, body: any): Promise<any> {
        const options = {
            method: "POST",
            body,
            json: true
        };

        const uri = `${this.serviceRootUri}/${relativeUri}`;
        return await rp(uri, options);
    }
}

export class Pwhaas implements IPwhaas {
    client: PwhaasClient;

    constructor(public clientOptions: any = defaultClientOptions) {
        this.client = new PwhaasClient(clientOptions);
    }

    async generateSalt(length: number): Promise<Buffer> {
        return await argon2.generateSalt(length);
    }

    private static async localHash(plain: string, salt: Buffer): Promise<string> {
        return await argon2.hash(plain, salt);
    }

    async hash(plain: string, salt: Buffer, maxtime?: number): Promise<IHashResponse> {
        const secretPlain = await Pwhaas.localHash(plain, salt);

        try {
            return await this.client.hash(secretPlain, maxtime);
        } catch (error) {
            const localHash = await Pwhaas.localHash(secretPlain, await this.generateSalt(defaultSaltLength));
            return { local: true, error, options: argon2.defaults, hash: localHash, timing: { salt: 0, hash: 0} };
        }
    }

    async verify(hash: string, plain: string, salt: Buffer): Promise<IVerifyResponse> {
        const secretPlain = await Pwhaas.localHash(plain, salt);

        //try to do the verify remotely. if fail, do it locally (ouch).
        try {
            return await this.client.verify(hash, secretPlain);
        } catch (error) {
            const localMatch = await argon2.verify(hash, secretPlain);
            return { local: true, error, match: localMatch, timing: { verify: 0} };
        }
    }
}

export const pwhaas: IPwhaas = new Pwhaas();