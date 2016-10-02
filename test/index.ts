import * as mocha from "mocha";
import * as chai from "chai";
import {pwhaas} from "../src/index";

describe("smoke test", () => {
    const plain = "😘 this is my really long 😀😂😂 passphrase that nobody will ever guess 🤓";

    it("can verify a hash", async (): Promise<any> => {
        const hash1 = await pwhaas.hash(plain);
        const verified = await pwhaas.verify(hash1, plain);
        chai.assert.isTrue(verified);
    });
});