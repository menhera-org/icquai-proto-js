
export function encode(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

export function decode(str: string): Uint8Array {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
