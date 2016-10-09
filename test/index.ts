import * as mocha from "mocha";
import * as chai from "chai";
import {pwhaas} from "../src/index";

describe("smoke test", () => {
    const plain = "😘 this is my really long 😀😂😂 passphrase that nobody will ever guess 🤓";

    it("can verify a hash", async function(): Promise<any> {
        this.timeout(0);

        await pwhaas.init();

        // Salt is used to hash the password locally before it goes to the service
        const salt = await pwhaas.generateSalt(32);

        const hashResponse = await pwhaas.hash(plain);
        chai.assert.isNotNull(hashResponse.hash);
        chai.assert.isString(hashResponse.hash);
        chai.assert.notEqual(hashResponse.hash, plain);

        const verifyResponse = await pwhaas.verify(hashResponse.hash, plain);
        chai.assert.isTrue(verifyResponse.match);
    });
});