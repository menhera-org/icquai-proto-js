
export function encode(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

export function decode(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}
