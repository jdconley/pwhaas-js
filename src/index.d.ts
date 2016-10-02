// Type definitions...

export class pwhaas {
    static hash(plain: string): Promise<string>;
    static verify(plain: string, hash:string): Promise<boolean>;
}