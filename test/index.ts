import * as mocha from "mocha";
import * as chai from "chai";
import {pwhaas, Pwhaas, defaultClientOptions, ClientOptions} from "../src/index";

describe("smoke test", () => {
    const plain = "😘 this is my really long 😀😂😂 passphrase that nobody will ever guess 🤓";

    it("can verify a hash", async function(): Promise<any> {
        this.timeout(0);

        const hashResponse = await pwhaas.hash(plain);
        console.log(hashResponse);
        chai.assert.isNotNull(hashResponse.hash, "hash is null");
        chai.assert.isString(hashResponse.hash, "hash is not a string");
        chai.assert.notEqual(hashResponse.hash, plain, "hash and plain are equal");
        chai.assert.isNotTrue(hashResponse.local, "hash was done locally");

        // Match
        const verifyResponse = await pwhaas.verify(hashResponse.hash, plain);
        console.log(verifyResponse);
        chai.assert.isTrue(verifyResponse.match, "plain not verified against hash");
        chai.assert.isNotTrue(verifyResponse.local, "hash was done locally");

        // No match
        const failVerifyResponse = await pwhaas.verify(hashResponse.hash, plain + "NOPE!");
        console.log(failVerifyResponse);
        chai.assert.isNotTrue(failVerifyResponse.match, "plain verified incorrectly against hash");
        chai.assert.isNotTrue(failVerifyResponse.local, "hash was done locally");

    });

    it("can hash locally", async function(): Promise<any> {
        this.timeout(0);

        const badPwhaas = new Pwhaas({
            "apiKey": defaultClientOptions().apiKey,
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

    it("sets options", () => {
        const target = new Pwhaas();
        const weirdOptions: ClientOptions = {
            apiKey: "bob",
            maxtime: 0,
            request: {
                timeout: 0
            },
            serviceRootUri: "bob"
        };

        target.setOptions(weirdOptions);
        chai.assert.equal(target.options.apiKey, weirdOptions.apiKey);
        chai.assert.equal(target.client.options.maxtime, weirdOptions.maxtime);
        chai.assert.equal(target.client.options.request.timeout, weirdOptions.request.timeout);
        chai.assert.equal(target.client.options.serviceRootUri, weirdOptions.serviceRootUri);

        // This should reset us to the defaults
        const defaultOptions = defaultClientOptions();
        target.setOptions({});
        chai.assert.equal(target.client.options.apiKey, defaultOptions.apiKey);
        chai.assert.equal(target.client.options.maxtime, defaultOptions.maxtime);
        chai.assert.equal(target.client.options.request.timeout, defaultOptions.request.timeout);
        chai.assert.equal(target.client.options.serviceRootUri, defaultOptions.serviceRootUri);
    });

    it("sets options from env", () => {
        process.env.PWHAAS_API_KEY = "bob";
        process.env.PWHAAS_MAX_TIME = "0";
        process.env.PWHAAS_ROOT_URI = "bob";
        process.env.PWHAAS_API_TIMEOUT = "0";


        const target = new Pwhaas();
        chai.assert.equal(target.options.apiKey, process.env.PWHAAS_API_KEY);
        chai.assert.equal(target.client.options.maxtime, process.env.PWHAAS_MAX_TIME);
        chai.assert.equal(target.client.options.request.timeout, process.env.PWHAAS_API_TIMEOUT);
        chai.assert.equal(target.client.options.serviceRootUri, process.env.PWHAAS_ROOT_URI);

        // This should reset us to the defaults
        process.env.PWHAAS_API_KEY = "";
        process.env.PWHAAS_MAX_TIME = "";
        process.env.PWHAAS_ROOT_URI = "";
        process.env.PWHAAS_API_TIMEOUT = "";

        const defaultOptions = defaultClientOptions();
        target.setOptions({});
        chai.assert.notEqual(target.options.apiKey, process.env.PWHAAS_API_KEY);
        chai.assert.notEqual(target.client.options.maxtime, process.env.PWHAAS_MAX_TIME);
        chai.assert.notEqual(target.client.options.request.timeout, process.env.PWHAAS_API_TIMEOUT);
        chai.assert.notEqual(target.client.options.serviceRootUri, process.env.PWHAAS_ROOT_URI);

        chai.assert.equal(target.options.apiKey, "[Your API Key Here]");
        chai.assert.equal(target.client.options.maxtime, 500);
        chai.assert.equal(target.client.options.request.timeout, 5000);
        chai.assert.equal(target.client.options.serviceRootUri, "https://api.pwhaas.com");
    });
});