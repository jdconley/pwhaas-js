export interface IOptions {
    hashLength:number;
    timeCost:number;
    memoryCost:number;
    parallelism:number;
    argon2d:boolean;
}

export interface INumericLimit {
    max:number;
    min:number;
}

export interface IOptionLimits {
    hashLength:INumericLimit;
    memoryCost:INumericLimit;
    timeCost:INumericLimit;
    parallelism:INumericLimit;
}

export const defaults:IOptions;
export const limits:IOptionLimits;
export function hash(plain:string, salt:Buffer|string, options?:IOptions):Promise<string>;
export function generateSalt(length:number):Promise<Buffer>;
export function verify(hash:string, plain:string):Promise<boolean>;
