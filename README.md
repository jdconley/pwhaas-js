[![Build Status](https://travis-ci.org/jdconley/pwhaas-js.svg?branch=master)](https://travis-ci.org/jdconley/pwhaas-js) [![npm version](https://badge.fury.io/js/pwhaas.svg)](https://badge.fury.io/js/pwhaas)

# pwhaas
A Node.JS client module for [pwhaas](https://github.com/jdconley/pwhaas). You
can host the pwhaas service yourself or use it at [pwhaas.com](https://www.pwhaas.com).

Pwhaas is a service that lets the good guys hash passwords with the same powerful hardware
used by attackers. This makes the attacker's job 100's of times harder as it increases the
amount of time they have to spend guessing the passwords.

This service offloads CPU intensive password hashing from your application servers so they
can do what they are good at and asynchronously wait on IO instead.

It hashes passwords with the latest recommended salt generating and memory-hard
algorithm optimized for x86: ([Argon2](https://github.com/P-H-C/phc-winner-argon2)).
It is designed to hash in parallel on high CPU count systems with up to 4GB of memory
utilized in order to make the resulting hashes difficult to crack with GPUs or ASIC
processors.

By default this module will connect to api.pwhaas.com and hash on a VM with 8 CPU cores.
It will hash for 1,000ms. For free. For higher security hashes utilizing 10's of CPU cores
in parallel, and higher performance servers running on metal (no VM) you'll have to sign
up for an account.

This module makes it easy to use the pwhaas service with the same interface
you would use to hash passwords locally. 

Pwhaas is resilient. If the pwhaas service is unavailable this module utilizes
[argon2themax](https://github.com/jdconley/argon2themax)
to find an expensive set of hash options and will compute the hash locally.

Your users' passwords are hashed with argon2 locally before sending them
to the pwhaas service. This helps protect them even if there is a MITM attack
or the pwhaas service itself is hacked.

## Installation
pwhaas depends on the [argon2](https://github.com/ranisalt/node-argon2) Node module, which
requires node-gyp to be installed globally. It also requires a modern
C++ compiler. Please see the [argon2 ReadMe](https://github.com/ranisalt/node-argon2)
for more information if you have trouble running `npm install`.

We require Node.JS v4.0.0+.

```sh
npm install -g node-gyp

npm install --save pwhaas
```

## Usage
If you are either hosting your own [pwhaas](https://github.com/jdconley/pwhaas) compatible
instance or have a paid account on [pwhaas.com](https://www.pwhaas.com) you'll want to set
some options. You can do this with either enviroment variables or with a Javascript object.

### Set options with environment variables
You can set the options via environment variables. Remember to keep your API Key private
and don't commit it to any public repos.

```sh

# Your API Key... The default will let you hash in a free trial mode, with less secure hashes.
export PWHAAS_API_KEY='[Your API Key Here]'

# The amount of time (ms) you want the service to spend hashing per password
export PWHAAS_MAX_TIME=250

# The URI to the API server. You shouldn't need to set this unless you are self hosting.
export PWHAAS_ROOT_URI='https://api.pwhaas.com'

# The amount of time to give the API (ms) before falling back to a local hash
export PWHAAS_API_TIMEOUT=5000

```

### Set options via code
If you want to, you can also set the options via a Javascript object. This can be done
with the `setOptions` function or when you make your call to `init`.

Remember to keep your API Key private and don't commit it to any public repos. Yes,
I repeated myself. :)

```js

pwhaas.setOptions({
    apiKey: "[Your API Key Here]",
    maxtime: 250,
    serviceRootUri: "https://api.pwhaas.com",
    request: {
        timeout: 5000
    }
});

// OR....

await pwhaas.init({
    apiKey: "[Your API Key Here]",
    maxtime: 250,
    serviceRootUri: "https://api.pwhaas.com",
    request: {
        timeout: 5000
    }
});

```

### Use the service

```js
// TypeScript / ES7
import { pwhaas } from "pwhaas";
const plain = "password";

// Init the service once before using it.
// This will find some secure hash options to use for local hashing in case pwhaas is unreachable.
await pwhaas.init({ apiKey: "[Your API Key Here]" });

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
```

```js

// JavaScript / ES5 / Promises instead of "await"
var pwhaas = require("pwhaas").pwhaas;

var plain = "password";

// Init the service once before using it.
// This will find some secure hash options to use for local hashing in case pwhaas is unreachable.
// Pass your API Key in here.
pwhaas.init({ apiKey: "[Your API Key Here]" })
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
        
        return verifyResponse.match;
    });
```

## Advanced Usage
You can also specify your api key and the service root uri when you `init` your pwhaas service.
 
The defaults global options are:

```json

{
    "apiKey": "[Your API Key Here]",
    "serviceRootUri": "https://api.pwhaas.com",
    "maxtime": 500
}

```

When you call `hash` you can specify the amount of time you would like pwhaas to
spend hashing. The service will choose options that will take close to that compute
time. By default it uses the `maxtime` specified during `init`. The service allows
you to utilize up to 1,000ms of compute time.

```js

// This would be a very secure hash...
const hashResponse = await pwhaas.hash("password", 1000);


```

If you want multiple instances of pwhaas with different configurations you can do that
as well. You can just instantiate the Pwhaas class and use it as shown in the examples
above that utilize the singleton.

```js

import { Pwhaas } from "pwhaas";

// You can specify options on the constructor of this class
const pwhaas = new Pwhaas({ apiKey: "[Your API Key Here]" });

const maxLocalOptions = await pwhaas.init();


```

```js

var Pwhaas = require("pwhaas").Pwhaas;

var pwhaas = new Pwhaas();

// You can also specify options on the init() function
pwhaas
    .init({ apiKey: "[Your API Key Here]" })
    .then(function(maxLocalOptions) {
        // pwhaas is ready to use!
    });

```