"use strict";

import * as argon2 from "argon2";
import * as os from "os";
import * as _ from "lodash";

export interface Timing {
    options: argon2.Options;
    computeTimeMs: number;
}

export interface TimingResult {
    timings: Timing[];
}

export interface TimingOptions {
    maxTimeMs: number;
    argon2d: boolean;
    saltLength: number;
    plain: string;
    statusCallback: (timing: Timing) => boolean;
}

export interface Strategy {
    run(options: TimingOptions): Promise<TimingResult>;
}

class MaxMemoryMarchStrategy implements Strategy {
    async run(options: TimingOptions): Promise<TimingResult> {
        // Use CPU count * 2 or the argon2 min limits for parallelism
        // March up toward the free system memory or argon2 memory limits
        // Stop when we hit maxTimeMs
        // If we don't hit maxTimeMs, start again at the next timeCost
        // Repeat

        const parallelism = Math.max(
            Math.min(os.cpus().length * 2, argon2.limits.parallelism.max),
            argon2.limits.parallelism.min);

        const memoryCostMax = Math.min(
            Math.floor(Math.log2(os.freemem() / 1024)),
            argon2.limits.memoryCost.max);

        const opts = _.clone(argon2.defaults);
        opts.argon2d = options.argon2d;
        opts.parallelism = parallelism;

        const salt = await argon2.generateSalt(options.saltLength);

        const result: TimingResult = {
            timings: []
        };

        let lastRunTime: number = 0;

        do {
            const startHrtime = process.hrtime();
            await argon2.hash(options.plain, salt, opts);
            const elapsedHrtime = process.hrtime(startHrtime);

            const timing: Timing = {
                computeTimeMs: lastRunTime = Argon2TheMax.hrtimeToMs(elapsedHrtime),
                options: _.clone(opts)
            };

            result.timings.push(timing);

            // Allow the callback to cancel the process if it feels the urge
            if (options.statusCallback && !options.statusCallback(timing)) {
                break;
            }

            // Prefer adding more memory, then add more time
            if (opts.memoryCost < memoryCostMax) {
                opts.memoryCost++;
            } else if (opts.timeCost < argon2.limits.timeCost.max) {
                opts.memoryCost = argon2.defaults.memoryCost;
                opts.timeCost++;
            } else {
                // Hit both the memory and time limits -- Is this a supercomputer?
                break;
            }
        } while (lastRunTime < options.maxTimeMs);

        return result;
    }

}

export class Argon2TheMax {
    public static defaultStrategy: Strategy = new MaxMemoryMarchStrategy();
    public static defaultTimingOptions: TimingOptions = {
        argon2d: false,
        maxTimeMs: 1000,
        plain: "this is a super cool password",
        saltLength: 32,
        statusCallback: Argon2TheMax.logStatus
    };

    static hrtimeToMs(hrtime: number[]): number {
        return hrtime[0] * 1e3 + hrtime[1] / 1e6;
    }

    private static logStatus(timing: Timing): boolean {
        console.log(`Took ${timing.computeTimeMs}ms.
            Parallelism: ${timing.options.parallelism}.
            MemoryCost: ${timing.options.memoryCost}.
            TimeCost: ${timing.options.timeCost}.`);

        return true;
    }

    static run(options?: TimingOptions, strategy?: Strategy): Promise<TimingResult> {
        strategy = strategy || Argon2TheMax.defaultStrategy;
        options = options || Argon2TheMax.defaultTimingOptions;

        return strategy.run(options);
    }
}