"use strict";

import * as argon2 from "argon2";
import * as rp from "request-promise";

export const defaultSaltLength: number = 32;
export const defaultMaxHashTimeMs: number = 500;
export var defaultClientOptions: any = {};

// These are the same defaults as argon2 lib.
// But we set them here for consistency across versions.
let hashOptions: argon2.Options = {
    hashLength: 32,
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    argon2d: false
};

export interface PwhaasService {
    hash(plain: string, maxtime?: number): Promise<HashResponse>;
    verify(hash: string, plain: string): Promise<VerifyResponse>;
    generateSalt(length: number): Promise<Buffer>;
}

export interface HashTiming {
    salt: number;
    hash: number;
}

export interface VerifyTiming {
    verify: number;
}

export interface HashResponse {
    local: boolean;
    options: argon2.Options;
    hash: string;
    timing: HashTiming;
    error: any;
}

export interface VerifyResponse {
    local: boolean;
    match: boolean;
    timing: VerifyTiming;
    error: any;
}

class HashRequest {
    constructor(public plain: string, public maxtime: number) {}
}

class VerifyRequest {
    constructor(public hash: string, public plain: string) {}
}

class PwhaasClient {
    serviceRootUri = "https://api.pwhaas.com";

    constructor(public options: any) {
    }

    async hash(plain: string, maxtime?: number): Promise<HashResponse> {
        const req = new HashRequest(plain, maxtime || defaultMaxHashTimeMs);

        return await this.postJson("hash", req);
    }

    async verify(hash: string, plain: string): Promise<VerifyResponse> {
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

        const localSalt = Buffer.from(parts[2], "base64");

        return new LocalHash(parts[3], localSalt);
    }

    toString(): string {
        const saltStr = this.localSalt.toString("base64");

        // Tag this so we know it is our hash, including a version field.
        // Colons are a reasonable/simple separator since salt is base64 encoded.
        // TODO: Persist the local argon2 options to support using non-defaults
        return `pwhaas:0:${saltStr}:${this.remoteHash}`;
    }
}

class Pwhaas implements PwhaasService {
    client: PwhaasClient;

    constructor(public clientOptions: any = defaultClientOptions) {
        this.client = new PwhaasClient(clientOptions);
    }

    async generateSalt(length: number): Promise<Buffer> {
        return await argon2.generateSalt(length);
    }

    async hash(plain: string, maxtime?: number): Promise<HashResponse> {
        const salt = await this.generateSalt(defaultSaltLength);
        const secretPlain = await argon2.hash(plain, salt, hashOptions);

        let hashResult: HashResponse;

        try {
            hashResult = await this.client.hash(secretPlain, maxtime);
        } catch (error) {
            const hash = await argon2.hash(secretPlain, await this.generateSalt(defaultSaltLength), hashOptions);
            hashResult = { local: true, error, options: argon2.defaults, hash: hash, timing: { salt: 0, hash: 0} };
        }

        // Replace the remote hash with our encoded hash.
        // This is so we can reproduce the operations used to recreate 
        // the hashed password during the verify step, without having to 
        // store the weaker intermediate hash anywhere.
        const localhash = new LocalHash(hashResult.hash, salt);
        hashResult.hash = localhash.toString();

        return hashResult;
    }

    async verify(hash: string, plain: string): Promise<VerifyResponse> {
        // Use the same salt we used when hashing locally before.
        const localHash = LocalHash.from(hash);
        const secretPlain = await argon2.hash(plain, localHash.localSalt, defaultClientOptions);

        // Try to do the verify remotely. If fail, do it locally (bummer).
        try {
            return await this.client.verify(localHash.remoteHash, secretPlain);
        } catch (error) {
            const localMatch = await argon2.verify(localHash.remoteHash, secretPlain);
            return { local: true, error, match: localMatch, timing: { verify: 0} };
        }
    }
}

export const pwhaas: PwhaasService = new Pwhaas();