"use strict";

import * as argon2 from "argon2themax";
import * as rp from "request-promise";
import * as _ from "lodash";

export const defaultSaltLength: number = 32;
export const defaultMaxHashTimeMs: number = 500;

export interface ClientOptions {
    serviceRootUri?: string;
    request?: rp.RequestPromiseOptions;
}

export const defaultClientOptions: ClientOptions = {
    serviceRootUri: "https://api.pwhaas.com",
    request: {
        method: "POST",
        json: true,
        timeout: 1000
    }
};

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
    init(): Promise<any>;
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
    options: ClientOptions;

    constructor(options: ClientOptions = defaultClientOptions) {
        this.options = _.assignIn({}, defaultClientOptions, options);
    }

    async hash(plain: string, maxtime?: number): Promise<HashResponse> {
        const req = new HashRequest(plain, maxtime || defaultMaxHashTimeMs);

        return await this.postJson("hash", req);
    }

    async verify(hash: string, plain: string): Promise<VerifyResponse> {
        const req = new VerifyRequest(hash, plain);

        return await this.postJson("verify", req);
    }

    private async postJson(relativeUri: string, body: any): Promise<any> {
        const requestOptions = _.cloneDeep(this.options.request);
        requestOptions.body = body;

        const uri = `${this.options.serviceRootUri}/${relativeUri}`;
        let result = await rp(uri, requestOptions);
        return result;
    }
}

class LocalHash {
    private static supportedHashVersions = {
        "0": true
    };

    static hashVersion = "0";

    constructor(public remoteHash: string, public localSalt: Buffer) {
    }

    static from(encodedHash: string): LocalHash {
        const parts = encodedHash.split(":", 4);
        if (parts.length !== 4 || parts[0] !== "pwhaas") {
            throw new Error("Unrecognized hash. Was it created with pwhaas?");
        }

        if (!LocalHash.supportedHashVersions[parts[1]]) {
            throw new Error("Unsupported hash version. Maybe you need to update pwhaas?");
        }

        const localSalt = Buffer.from(parts[2], "base64");

        return new LocalHash(parts[3], localSalt);
    }

    toString(): string {
        const saltStr = this.localSalt.toString("base64");

        // Tag this so we know it is our hash, including a version field.
        // Colons are a reasonable/simple separator since salt is base64 encoded.
        // TODO: Include the local argon2 options to support using non-defaults
        return `pwhaas:${LocalHash.hashVersion}:${saltStr}:${this.remoteHash}`;
    }
}

class Pwhaas implements PwhaasService {
    client: PwhaasClient;
    maxLocalOptions: argon2.Options;

    constructor(public clientOptions: ClientOptions = defaultClientOptions) {
        this.client = new PwhaasClient(clientOptions);
    }

    async init(): Promise<any> {
        this.maxLocalOptions = await argon2.getMaxOptions();
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
            if (!this.maxLocalOptions) {
                await this.init();
            }

            const hash = await argon2.hash(secretPlain, await this.generateSalt(defaultSaltLength), this.maxLocalOptions);
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