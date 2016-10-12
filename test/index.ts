import * as mocha from "mocha";
import * as chai from "chai";
import {pwhaas, Pwhaas, defaultClientOptions} from "../src/index";

describe("smoke test", () => {
    const plain = "😘 this is my really long 😀😂😂 passphrase that nobody will ever guess 🤓";

    it("can verify a hash", async function(): Promise<any> {
        this.timeout(0);

        const hashResponse = await pwhaas.hash(plain);
        console.log(hashResponse);
        chai.assert.isNotNull(hashResponse.hash);
        chai.assert.isString(hashResponse.hash);
        chai.assert.notEqual(hashResponse.hash, plain);
        chai.assert.isNotTrue(hashResponse.local);

        // Match
        const verifyResponse = await pwhaas.verify(hashResponse.hash, plain);
        console.log(verifyResponse);
        chai.assert.isTrue(verifyResponse.match);
        chai.assert.isNotTrue(verifyResponse.local);

        // No match
        const failVerifyResponse = await pwhaas.verify(hashResponse.hash, plain + "NOPE!");
        console.log(failVerifyResponse);
        chai.assert.isNotTrue(failVerifyResponse.match);
        chai.assert.isNotTrue(failVerifyResponse.local);
    });

    it("can hash locally", async function(): Promise<any> {
        this.timeout(0);

        const badPwhaas = new Pwhaas({
            "apiKey": defaultClientOptions.apiKey,
            "serviceRootUri": "http://sjksdfjklfsandsnfjwefklfahsdlkflasjgha.com"
        });

        const hashResponse = await badPwhaas.hash(plain);
        console.log(hashResponse);
        chai.assert.isNotNull(hashResponse.hash);
        chai.assert.isString(hashResponse.hash);
        chai.assert.notEqual(hashResponse.hash, plain);
        chai.assert.isTrue(hashResponse.local);

        // Match
        const verifyResponse = await badPwhaas.verify(hashResponse.hash, plain);
        console.log(verifyResponse);
        chai.assert.isTrue(verifyResponse.match);
        chai.assert.isTrue(verifyResponse.local);

        // No match
        const failVerifyResponse = await badPwhaas.verify(hashResponse.hash, plain + "NOPE!");
        console.log(failVerifyResponse);
        chai.assert.isNotTrue(failVerifyResponse.match);
        chai.assert.isTrue(failVerifyResponse.local);
    });
});