"use strict";

import * as argon2 from "argon2";
import * as rp from "request-promise";

export const defaultSaltLength: number = 32;
export const defaultMaxHashTimeMs: number = 500;
export var defaultClientOptions: any = {};

//TODO: Don't require passing in the salt for the local hashing -- store it in the "hash" returned in the hash() method and read it during verify
export interface IPwhaas {
    hash(plain: string, maxtime?: number): Promise<IHashResponse>;
    verify(hash: string, plain: string): Promise<IVerifyResponse>;
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
    error: any;
}

export interface IVerifyResponse {
    local: boolean;
    match: boolean;
    timing: IVerifyTiming;
    error: any;
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

class LocalHash {
    constructor(public remoteHash: string, public localSalt: Buffer) {
    }

    static from(encodedHash: string): LocalHash {
        const parts = encodedHash.split(":", 4);
        if (parts.length !== 4 || parts[0] !== "pwhaas") {
            throw new Error("Unrecognized hash. Was it created with pwhaas?");
        }

        // TODO: Remember the rest of the local argon2 options to support using non-defaults and version changes
        const localSalt = Buffer.from(parts[2], "base64");

        return new LocalHash(parts[3], localSalt);
    }

    toString(): string {
        const saltStr = this.localSalt.toString("base64");

        // keep track of our options, including a version field.
        // colons are a reasonable/simple separator since salt is base64 encoded.
        return `pwhaas:0:${saltStr}:${this.remoteHash}`;
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

    async hash(plain: string, maxtime?: number): Promise<IHashResponse> {
        const salt = await this.generateSalt(defaultSaltLength);
        const secretPlain = await Pwhaas.localHash(plain, salt);

        let hashResult: IHashResponse;

        try {
            hashResult = await this.client.hash(secretPlain, maxtime);
        } catch (error) {
            const hash = await Pwhaas.localHash(secretPlain, await this.generateSalt(defaultSaltLength));
            hashResult = { local: true, error, options: argon2.defaults, hash: hash, timing: { salt: 0, hash: 0} };
        }

        // replace the remote hash with our encoded hash
        // this is so we can reproduce the operations to recreate the hashed password during the verify step 
        const localhash = new LocalHash(hashResult.hash, salt);
        hashResult.hash = localhash.toString();
        return hashResult;
    }

    async verify(hash: string, plain: string): Promise<IVerifyResponse> {
        // use the same salt we used when hashing locally before
        const localHash = LocalHash.from(hash);
        const secretPlain = await Pwhaas.localHash(plain, localHash.localSalt);

        // try to do the verify remotely. if fail, do it locally (ouch).
        try {
            return await this.client.verify(localHash.remoteHash, secretPlain);
        } catch (error) {
            const localMatch = await argon2.verify(localHash.remoteHash, secretPlain);
            return { local: true, error, match: localMatch, timing: { verify: 0} };
        }
    }
}

export const pwhaas: IPwhaas = new Pwhaas();