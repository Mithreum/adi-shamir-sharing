/* tslint:disable */
/* eslint-disable */
/**
 * Splits a secret key into 4 parts.
 *
 * This function expects the secret as a hexadecimal string, and returns a JsValue
 * representing an array of TSShare objects. It uses a fixed threshold and share count of 4,
 * meaning that all 4 shares are required to reconstruct the key.
 *
 * # Arguments
 *
 * * `secret` - The secret key as a hexadecimal string.
 *
 * # Returns
 *
 * A JsValue containing an array of TSShare objects.
 */
export function split_key(secret: string): any;
/**
 * Reconstructs a secret key from an array of TSShare objects.
 *
 * The shares must be provided as a JsValue representing an array where each element has
 * `x` and `y` fields (both hexadecimal strings). This function returns the reconstructed
 * secret as a hexadecimal string.
 *
 * # Arguments
 *
 * * `shares` - A JsValue representing an array of share objects.
 *
 * # Returns
 *
 * The reconstructed secret key as a hexadecimal string.
 */
export function reconstruct_key(shares: any): string;
/**
 * Splits a Solana key (a 128‑hex-character string) into two halves and secret‐shares each half.
 * Returns a JsValue representing an object with two properties: `sol_part_1` and `sol_part_2`,
 * each an array of TSShare objects.
 *
 * # Arguments
 *
 * * `secret` - A Solana private key represented as a 128‑hex-character string.
 *
 * # Errors
 *
 * Returns an error if the key is not exactly 128 hex characters.
 */
export function split_solana_key(secret: string): any;
/**
 * Reconstructs a full Solana key from the shares of its two halves.
 * It expects a JsValue representing an object with properties `sol_part_1` and `sol_part_2`, each being
 * an array of TSShare objects. It returns the 128‑hex-character string corresponding to the combined key.
 */
export function reconstruct_solana_key(sol_parts: any): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly split_key: (a: number, b: number) => [number, number, number];
  readonly reconstruct_key: (a: any) => [number, number, number, number];
  readonly split_solana_key: (a: number, b: number) => [number, number, number];
  readonly reconstruct_solana_key: (a: any) => [number, number, number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
