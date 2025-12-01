import {jubjub} from "@noble/curves/misc";
import {EdwardsPoint} from "@noble/curves/abstract/edwards";
import {poseidon2} from 'poseidon-bls12381';
import {
    addHexPrefix,
    Address,
    utf8ToBytes,
    bigIntToBytes,
    bytesToBigInt,
    bytesToHex,
    concatBytes,
    hexToBigInt,
    hexToBytes,
    setLengthLeft
} from "@ethereumjs/util"

const POSEIDON_INPUTS = 2;
export const DST_NONCE = setLengthLeft(utf8ToBytes("TokamakAuth‑EDDSA‑NONCE‑v1"), 32)

export const poseidon_raw = (inVals: bigint[]): bigint => {
    if (inVals.length !== POSEIDON_INPUTS) {
        throw new Error(`Expected an array with ${POSEIDON_INPUTS} elements, but got ${inVals.length} elements`)
    }
    return poseidon2(inVals)
}
export const poseidonN = (in_vals: bigint[]): bigint => {
    if (in_vals.length !== POSEIDON_INPUTS) {
        throw new Error(`poseidon${POSEIDON_INPUTS} expected exactly ${POSEIDON_INPUTS} values`)
    }
    return poseidon_raw(in_vals)
}

export function batchBigIntTo32BytesEach(...inVals: bigint[]): Uint8Array {
    return concatBytes(...inVals.map(x => setLengthLeft(bigIntToBytes(x), 32)))
}

/**
 * PoseidonN2xCompress
 */
export const poseidonN2xCompress = (in_vals: bigint[]): bigint => {
    if (in_vals.length !== POSEIDON_INPUTS ** 2) {
        throw new Error(`poseidon${POSEIDON_INPUTS} expected exactly ${POSEIDON_INPUTS ** 2} values`)
    }

    const interim: bigint[] = []
    for (var k = 0; k < POSEIDON_INPUTS; k++) {
        const children = in_vals.slice(k * POSEIDON_INPUTS, (k + 1) * POSEIDON_INPUTS)
        interim.push(poseidon_raw(children))
    }
    return poseidon_raw(interim)
}

export function eddsaSign(prvKey: bigint, msg: Uint8Array[]): {
    randomizer: EdwardsPoint,
    signature: bigint
} {
    const pubKey = jubjub.Point.BASE.multiply(prvKey)
    let s: bigint = 0n
    let R: EdwardsPoint = jubjub.Point.ZERO
    while (R.equals(jubjub.Point.ZERO) || s === 0n) {
        const secretKeyBytes = poseidon_btree_hasher(concatBytes(
            DST_NONCE,
            setLengthLeft(bigIntToBytes(prvKey), 32),
        ))

        const r = bytesToBigInt(poseidon_btree_hasher(concatBytes(
            DST_NONCE,
            secretKeyBytes,
            batchBigIntTo32BytesEach(
                pubKey.toAffine().x,
                pubKey.toAffine().y
            ),
            ...msg,
        ))) % jubjub.Point.Fn.ORDER

        R = jubjub.Point.BASE.multiply(r)

        const e = bytesToBigInt(poseidon_btree_hasher(concatBytes(
            batchBigIntTo32BytesEach(
                R.toAffine().x,
                R.toAffine().y,
                pubKey.toAffine().x,
                pubKey.toAffine().y
            ),
            ...msg
        )))
        const ep = e % jubjub.Point.Fn.ORDER

        s = (r + ep * prvKey) % jubjub.Point.Fn.ORDER
    }
    return {
        signature: s,
        randomizer: R,
    }
}

export function eddsaVerify(msg: Uint8Array[], pubKey: EdwardsPoint, randomizer: EdwardsPoint, signature: bigint): boolean {

    if (pubKey.equals(jubjub.Point.ZERO)) return false
    if (randomizer.equals(jubjub.Point.ZERO)) return false
    if (msg.length === 0) return false

    console.log("rx ", randomizer.toAffine().x.toString(16))
    console.log("ry ", randomizer.toAffine().y.toString(16))
    console.log("px ", pubKey.toAffine().x.toString(16))
    console.log("py ", pubKey.toAffine().y.toString(16))
    console.log("msg ", bytesToHex(msg[0]))

    if (signature >= jubjub.Point.Fn.ORDER || signature < 0n){
        return false
    }

    const e = bytesToBigInt(poseidon_btree_hasher(concatBytes(
        batchBigIntTo32BytesEach(
            randomizer.toAffine().x,
            randomizer.toAffine().y,
            pubKey.toAffine().x,
            pubKey.toAffine().y
        ),
        ...msg
    ))) % jubjub.Point.Fn.ORDER
    // Recommended (secure) check
    const LHS = jubjub.Point.BASE.multiply(signature);
    const RHS = pubKey.multiply(e).add(randomizer);

// Multiply both sides by the cofactor (8)
    const cofactoredLHS = LHS.multiply(8n);
    const cofactoredRHS = RHS.multiply(8n);

    return cofactoredLHS.equals(cofactoredRHS);
}

export function poseidon_btree_hasher(msg: Uint8Array): Uint8Array {
    if (msg.length === 0) {
        return setLengthLeft(bigIntToBytes(poseidon_raw(Array<bigint>(POSEIDON_INPUTS).fill(0n))), 32)
    }
    // Split input bytes into 32-byte big-endian words → BigInt[] (no Node Buffer dependency)
    const words: bigint[] = Array.from({length: Math.ceil(msg.byteLength / 32)}, (_, i) => {
        const slice = msg.subarray(i * 32, (i + 1) * 32)
        return bytesToBigInt(slice)
    });

    const fold = (arr: bigint[]): bigint[] => {
        const n1xChunks = Math.ceil(arr.length / POSEIDON_INPUTS);
        const nPaddedChildren = n1xChunks * POSEIDON_INPUTS;

        const mode2x: boolean = nPaddedChildren % (POSEIDON_INPUTS ** 2) === 0

        let placeFunction = mode2x ?
            poseidonN2xCompress :
            poseidonN

        const nChildren = mode2x ? (POSEIDON_INPUTS ** 2) : POSEIDON_INPUTS

        const out: bigint[] = [];
        for (let childId = 0; childId < nPaddedChildren; childId += nChildren) {
            const chunk = Array.from({length: nChildren}, (_, localChildId) => arr[childId + localChildId] ?? 0n);
            // Every word must be within the field [0, MOD)
            // chunk.map(checkBLS12Modulus)
            out.push(placeFunction(chunk));
        }
        return out;
    };

    // Repeatedly fold until a single word remains
    let acc: bigint[] = fold(words)
    while (acc.length > 1) acc = fold(acc)
    return setLengthLeft(bigIntToBytes(acc[0]), 32);
}
