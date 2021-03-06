"use strict";

import * as argon2 from "argon2themax";
import * as rp from "request-promise";
import * as _ from "lodash";

export interface ClientOptions {
    apiKey?: string;
    serviceRootUri?: string;
    maxtime?: number;
    request?: rp.RequestPromiseOptions;
    disableLocalHashingFallback?: boolean;
    disablePreHash?: boolean;
}

const pwhaasDefaultApiKey = "[Your API Key Here]";
const pwhaasDefaultApiRootUri = "https://api.pwhaas.com";

export const defaultClientOptions: () => ClientOptions = () => {
    return {
        apiKey: process.env.PWHAAS_API_KEY || pwhaasDefaultApiKey,
        maxtime: process.env.PWHAAS_MAX_TIME ? parseInt(process.env.PWHAAS_MAX_TIME) : 500,
        serviceRootUri: process.env.PWHAAS_ROOT_URI || pwhaasDefaultApiRootUri,
        request: {
            method: "POST",
            json: true,
            timeout: process.env.PWHAAS_API_TIMEOUT ? parseInt(process.env.PWHAAS_API_TIMEOUT) : 5000
        },
        disableLocalHashingFallback: !!process.env.PWHAAS_DISABLE_LOCAL_HASHING_FALLBACK,
        disablePreHash: !!process.env.PWHAAS_DISABLE_PRE_HASH
    };
};

// These are the same defaults as argon2 lib.
// But we set them here for consistency across versions.
let hashOptions: argon2.Options = {
    hashLength: 32,
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    type: argon2.argon2i
};

export interface PwhaasService {
    init(options?: ClientOptions): Promise<argon2.Options>;
    hash(plain: string | Buffer, maxtime?: number): Promise<HashResponse>;
    verify(hash: string, plain: string | Buffer): Promise<VerifyResponse>;
    generateSalt(length?: number): Promise<Buffer>;
    setOptions(options: ClientOptions): void;
    readonly options: ClientOptions;
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

export class PwhaasClient {
    options: ClientOptions;

    constructor(options: ClientOptions = defaultClientOptions()) {
        this.setOptions(options);
    }

    setOptions(options: ClientOptions) {
        this.options = _.assignIn({}, defaultClientOptions(), options);
    }

    async hash(plain: string, maxtime: number = this.options.maxtime): Promise<HashResponse> {
        const req = new HashRequest(plain, maxtime);

        return await this.postJson("hash", req);
    }

    async verify(hash: string, plain: string): Promise<VerifyResponse> {
        const req = new VerifyRequest(hash, plain);

        return await this.postJson("verify", req);
    }

    private async postJson(relativeUri: string, body: any): Promise<any> {
        const requestOptions = _.cloneDeep(this.options.request);
        requestOptions.body = body;
        requestOptions.auth = {
            user: this.options.apiKey,
            sendImmediately: true
        };

        const uri = `${this.options.serviceRootUri}/${relativeUri}`;
        let result = await rp(uri, requestOptions);
        return result;
    }
}

class LocalHash {
    private static supportedHashVersions = {
        "0": true, // Initial version
        "1": true  // Supports no pre-hashing
    };

    static hashVersion = "1";

    constructor(public remoteHash: string, public localSalt: Buffer, public preHashDisabled?: boolean) {
    }

    static from(encodedHash: string): LocalHash {
        const parts = encodedHash.split(":", 4);
        if (parts.length !== 4 || parts[0] !== "pwhaas") {
            throw new Error("Unrecognized hash. Was it created with pwhaas?");
        }

        const hashVersion = parts[1];
        if (!LocalHash.supportedHashVersions[hashVersion]) {
            throw new Error("Unsupported hash version. Maybe you need to update pwhaas?");
        }

        // Version 0 required a salt
        if (hashVersion === "0") {
            const localSalt = Buffer.from(parts[2], "base64");

            return new LocalHash(parts[3], localSalt);
        }

        // Version 1 no longer requires salt
        // If salt is not included, we assume local hash was disabled
        if (hashVersion === "1") {
            const encodedSalt = parts[2];
            const localSalt = encodedSalt ? Buffer.from(encodedSalt, "base64") : null;

            return new LocalHash(parts[3], localSalt, !localSalt);
        }

        // This is unreachable
        // Leaving it here as a reminder to add in parsing code when the version changes
        throw new Error(`Parser not implemented for hash version "${parts[1]}". Implement one.`);
    }

    toString(): string {
        const saltStr = this.localSalt ? this.localSalt.toString("base64") : "";

        // Tag this so we know it is our hash, including a version field.
        // Colons are a reasonable/simple separator since salt is base64 encoded.
        // TODO: Include the local argon2 options to support using non-defaults
        return `pwhaas:${LocalHash.hashVersion}:${saltStr}:${this.remoteHash}`;
    }
}

export class Pwhaas implements PwhaasService {
    client: PwhaasClient;
    maxLocalOptions: argon2.Options;
    logOutput: (output: any) => void = console.log;

    constructor(clientOptions: ClientOptions = defaultClientOptions()) {
        this.client = new PwhaasClient(clientOptions);
    }

    get options(): ClientOptions {
        return this.client.options;
    }

    setOptions(options: ClientOptions): void {
        this.client.setOptions(options);
    }

    async init(options?: ClientOptions): Promise<argon2.Options> {
        if (options) {
            this.setOptions(options);
        };

        // Don't need to get max options if we do not do hash locally
        if (!this.options.disableLocalHashingFallback) {
            this.maxLocalOptions = await argon2.getMaxOptions();
        }
        return this.maxLocalOptions;
    }

    async generateSalt(length?: number): Promise<Buffer> {
        return await argon2.generateSalt(length);
    }

    private static hrTimeToMs(hrTime: [number, number]): number {
        return hrTime[0] * 1e3 + hrTime[1] / 1e6;
    }

    async hash(plain: string, maxtime: number = this.options.maxtime): Promise<HashResponse> {
        // A little marketing... More security for little cost is better, right?
        if (this.options.apiKey === pwhaasDefaultApiKey &&
            this.options.serviceRootUri === pwhaasDefaultApiRootUri) {
                this.logOutput(`pwhaas: Using free trial account. Sign up at pwhaas.com for a more secure hash. Plans starting at only $10/mo.`);
        }

        const startHrTime = process.hrtime();

        let secretPlain = plain;
        let saltElapsedHr = startHrTime;
        let salt: Buffer = null;
        if (!this.options.disablePreHash) {
            salt = await this.generateSalt();
            saltElapsedHr = process.hrtime(startHrTime);
            secretPlain = await argon2.hash(plain, salt, hashOptions);
        }

        let hashResult: HashResponse;

        try {
            hashResult = await this.client.hash(secretPlain, maxtime);
        } catch (error) {
            // We may be configured to not hash locally -- just throw the error
            if (this.options.disableLocalHashingFallback) {
                throw error;
            }

            if (!this.maxLocalOptions) {
                await this.init();
            }
            const salt = await this.generateSalt();

            const hashStartHrTime = process.hrtime();
            const hash = await argon2.hash(
                secretPlain, salt, this.maxLocalOptions);
            const hashElapsedHrTime = process.hrtime(hashStartHrTime);

            hashResult = {
                local: true,
                error,
                options: this.maxLocalOptions,
                hash,
                timing: {
                    salt: Pwhaas.hrTimeToMs(saltElapsedHr),
                    hash: Pwhaas.hrTimeToMs(hashElapsedHrTime)
                }
            };
        }

        // Replace the remote hash with our encoded hash.
        // This is so we can reproduce the operations used to recreate 
        // the hashed password during the verify step, without having to 
        // store the weaker intermediate hash anywhere.
        const localhash = new LocalHash(hashResult.hash, salt, this.options.disablePreHash);
        hashResult.hash = localhash.toString();

        const elapsedHrTime = process.hrtime(startHrTime);

        const overallDesc = hashResult.local
            ? `pwhaas: API UNAVAILABLE. Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`
            : `pwhaas: Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`;

        const hashDesc = `Hash: ${hashResult.timing.hash}ms.`;
        const threadsDesc = `Threads: ${hashResult.options.parallelism}`;
        const memoryDesc = `Memory: ${Math.pow(2, hashResult.options.memoryCost) / 1024}MB`;
        const iterationsDesc = `Iterations: ${hashResult.options.timeCost}`;

        this.logOutput(`${overallDesc} ${hashDesc} ${threadsDesc} ${memoryDesc} ${iterationsDesc}`);

        return hashResult;
    }

    async verify(hash: string, plain: string): Promise<VerifyResponse> {
        // A little marketing... More security for little cost is better, right?
        if (this.options.apiKey === pwhaasDefaultApiKey &&
            this.options.serviceRootUri === pwhaasDefaultApiRootUri) {
                this.logOutput(`pwhaas: Using free trial account. Sign up at pwhaas.com for a more secure hash. Plans starting at only $10/mo.`);
        }

        const startHrTime = process.hrtime();

        // Use the same salt we used when hashing locally before.
        const localHash = LocalHash.from(hash);
        let secretPlain = plain;
        if (!localHash.preHashDisabled) {
            secretPlain = await argon2.hash(plain, localHash.localSalt, hashOptions);
        }

        // Try to do the verify remotely. If fail, do it locally (bummer).
        let verifyResp: VerifyResponse;
        try {
            verifyResp = await this.client.verify(localHash.remoteHash, secretPlain);
        } catch (error) {
            if (this.options.disableLocalHashingFallback) {
                throw error;
            }

            const verifyStart = process.hrtime();
            const localMatch = await argon2.verify(localHash.remoteHash, secretPlain);
            const verifyElapsed = process.hrtime(verifyStart);

            verifyResp = {
                local: true,
                error,
                match: localMatch,
                timing: {
                    verify: Pwhaas.hrTimeToMs(verifyElapsed)
                }
            };
        }

        const elapsedHrTime = process.hrtime(startHrTime);

        const overallDesc = verifyResp.local
            ? `pwhaas: API UNAVAILABLE. Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`
            : `pwhaas: Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`;

        const hashDesc = `Verify: ${verifyResp.timing.verify}ms.`;

        this.logOutput(`${overallDesc} ${hashDesc}`);

        return verifyResp;
    }
}

export const pwhaas: PwhaasService = new Pwhaas();