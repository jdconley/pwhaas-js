var mocha = require("mocha");
var chai = require("chai");
var pwhaas = require("../src/index").pwhaas;

describe("can run the examples in Javascript", function() {
    it("can set options in js", function () {
        this.timeout(0);

    var plain = "password";

    // Init the service once before using it.
    // This will find some secure hash options to use for local hashing in case pwhaas is unreachable.
    // Pass your API Key in here.
    return pwhaas.init({ apiKey: "[Your API Key Here]" })
        .then(function() {

            // Hashing happens in an asynchronous event using libuv so your system can
            // still process other IO items in the Node.JS queue, such as web requests.
            return pwhaas.hash(plain);

        }).then(function(hashResponse) {

            // This hash is what you should store in your database. Treat it as an opaque string.
            // The response also contains information on how long the hashing took, the
            // Argon2 options that were used, and whether or not we had to fall back to hashing locally.
            console.log(hashResponse.hash);

            // Verifying the hash against your user's password is simple.
            return pwhaas.verify(hashResponse.hash, plain);

        }).then(function(verifyResponse) {
            
            // Does this password match the hash?
            console.log(verifyResponse.match);
            
            chai.assert.isTrue(verifyResponse.match, "password didn't verify");

            return verifyResponse.match;
        });
    });
});