
import { sha256 } from '@noble/hashes/sha2';

export class TimeIndexedScheme {
    public static readonly HOUR = new TimeIndexedScheme(3600000);

    public readonly tick: number;

    public constructor(tick: number) {
        if (tick <= 0) {
            throw new RangeError("Tick must be positive");
        }
        if (!Number.isSafeInteger(tick)) {
            throw new RangeError("Tick must be a safe integer");
        }
        this.tick = tick;
    }

    public indexFromMilliseconds(milliseconds: number): number {
        return 0 | (milliseconds / this.tick);
    }

    public indexFromSeconds(seconds: number): number {
        return 0 | (seconds * 1000 / this.tick);
    }

    public currentIndex(): number {
        return this.indexFromMilliseconds(Date.now());
    }
}

export interface TimeIndexedKey {
    readonly timeIndex: number;
    readonly key: Uint8Array; // 32 bytes
}

export const TimeIndexedKey = {
    hashMultiple(count: number, data: Uint8Array): Uint8Array {
        for (let i = 0; i < count; i++) {
            data = sha256(data);
        }
        return data;
    },

    forward(targetTimeIndex: number, indexedKey: TimeIndexedKey): TimeIndexedKey {
        const { timeIndex, key } = indexedKey;
        if (timeIndex > targetTimeIndex) {
            throw new RangeError("Cannot forward to a previous time index");
        }
        const count = targetTimeIndex - timeIndex;
        return { timeIndex: targetTimeIndex, key: TimeIndexedKey.hashMultiple(count, key) };
    },
};
