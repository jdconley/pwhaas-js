import * as mocha from "mocha";
import * as chai from "chai";
import { pwhaas, Pwhaas } from "../src/index";

describe("can run the examples", () => {

    it("can set options", function() {
        pwhaas.setOptions({
            apiKey: "[Your API Key Here]",
            maxtime: 250,
            serviceRootUri: "https://api.pwhaas.com",
            request: {
                timeout: 5000
            }
        });

        //back to default options so we don't screw with other tests
        pwhaas.setOptions({});
    });

    it("can do the basic example", async function(): Promise<any> {
        this.timeout(0);
        const plain = "password";

        // Init the service once before using it.
        // This will find some secure hash options to use for local hashing in case pwhaas is unreachable.
        await pwhaas.init();

        // Hashing happens in an asynchronous event using libuv so your system can
        // still process other IO items in the Node.JS queue, such as web requests.
        const hashResponse = await pwhaas.hash(plain);

        // This hash is what you should store in your database. Treat it as an opaque string.
        // The response also contains information on how long the hashing took, the
        // Argon2 options that were used, and whether or not we had to fall back to hashing locally.
        console.log(hashResponse.hash);

        // Verifying the hash against your user's password is simple.
        const verifyResponse = await pwhaas.verify(hashResponse.hash, plain);

        console.log(verifyResponse.match);
        chai.assert.isTrue(verifyResponse.match, "password doesn't match hash");
    });

    it("can do a non-default timing", async function(): Promise<any> {
        this.timeout(0);

        const hashResponse = await pwhaas.hash("password", 1000);

        chai.assert.isNotNull(hashResponse.hash, "didn't actually hash");
        chai.assert.isNotTrue(hashResponse.local, "password doesn't match hash");
    });

    it("can create an instance of Pwhaas", async function(): Promise<any> {
        this.timeout(0);

        const pwhaas = new Pwhaas({ apiKey: "[Your API Key Here]" });

        await pwhaas.init();

        const hashResponse = await pwhaas.hash("password", 100);

        chai.assert.isNotNull(hashResponse.hash, "didn't actually hash");
        chai.assert.isNotTrue(hashResponse.local, "password doesn't match hash");
    });
});