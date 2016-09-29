// Type definitions...
import {Promise} from "es6-promise";

export class pwhaas {
    static hash(plain: string): Promise<string>;
    static verify(plain: string, hash:string): Promise<boolean>;
}