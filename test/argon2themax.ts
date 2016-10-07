import * as mocha from "mocha";
import * as chai from "chai";
import { Argon2TheMax } from "../src/argon2themax";

describe("Turn it to 11", () => {
    it("can hash for a second", async function (): Promise<any> {
        this.timeout(60000);
        const result = await Argon2TheMax.run();
        console.log(`Found ${result.timings.length} timings.`);
    });
});