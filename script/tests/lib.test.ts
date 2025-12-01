import { eddsaSign, eddsaVerify, poseidonN2xCompress, poseidonN, poseidon_btree_hasher, batchBigIntTo32BytesEach } from "../src/lib";
import {
    jubjub } from "@noble/curves/misc";
import {bigIntToBytes, setLengthLeft} from "@ethereumjs/util";
import {bytesToNumberBE, bytesToHex, hexToBytes, bytesToNumberLE} from "@noble/curves/utils";


describe("lib.ts functions", () => {
  describe("poseidonN", () => {
    it("should hash two bigints correctly", () => {
      const inputs = [1n, 2n];
      const result = poseidonN(inputs);
      expect(typeof result).toBe("bigint");
      expect(result).toBeGreaterThan(0n);
    });

    it("should throw error for wrong number of inputs", () => {
      expect(() => poseidonN([1n])).toThrow("poseidon2 expected exactly 2 values");
      expect(() => poseidonN([1n, 2n, 3n])).toThrow("poseidon2 expected exactly 2 values");
    });
  });

  describe("poseidonN2xCompress", () => {
    it("should compress four bigints correctly", () => {
      const inputs = [1n, 2n, 3n, 4n];
      const result = poseidonN2xCompress(inputs);
      expect(typeof result).toBe("bigint");
      expect(result).toBeGreaterThan(0n);
    });

    it("should throw error for wrong number of inputs", () => {
      expect(() => poseidonN2xCompress([1n, 2n, 3n])).toThrow("poseidon2 expected exactly 4 values");
      expect(() => poseidonN2xCompress([1n, 2n, 3n, 4n, 5n])).toThrow("poseidon2 expected exactly 4 values");
    });
  });

  describe("poseidon", () => {
    it("should hash empty message", () => {
      const result = poseidon_btree_hasher(new Uint8Array());
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it("should hash a short message", () => {
      const msg = new Uint8Array([1, 2, 3, 4]);
      const result = poseidon_btree_hasher(msg);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it("should hash a longer message", () => {
      const msg = new Uint8Array(100).fill(42);
      const result = poseidon_btree_hasher(msg);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });
  });

  describe("eddsaSign and eddsaVerify", () => {
    it("should sign and verify a message correctly", () => {
      const prvKey = 123456789n; // Example private key
      const msg = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];

      const { randomizer, signature } = eddsaSign(prvKey, msg);
      const pubKey = jubjub.Point.BASE.multiply(prvKey);

      const isValid = eddsaVerify(msg, pubKey, randomizer, signature);
      expect(isValid).toBe(true);
    });

    it("should fail verification with wrong signature", () => {
      const prvKey = 123456789n;
      const msg = [new Uint8Array([1, 2, 3])];

      const { randomizer } = eddsaSign(prvKey, msg);
      const pubKey = jubjub.Point.BASE.multiply(prvKey);

      const isValid = eddsaVerify(msg, pubKey, randomizer, 999n); // Wrong signature
      expect(isValid).toBe(false);
    });

    it("should fail verification with wrong public key", () => {
      const prvKey = 123456789n;
      const msg = [new Uint8Array([1, 2, 3])];

      const { randomizer, signature } = eddsaSign(prvKey, msg);
      const wrongPubKey = jubjub.Point.BASE.multiply(987654321n); // Wrong key

      const isValid = eddsaVerify(msg, wrongPubKey, randomizer, signature);
      expect(isValid).toBe(false);
    });

    it("should serialize public key to bytes", () => {
      const prvKey = 123456789n;
      const pubKey = jubjub.Point.BASE.multiply(prvKey);
      const pubKeyBytes = pubKey.toBytes();
      expect(pubKeyBytes).toBeInstanceOf(Uint8Array);
      expect(pubKeyBytes.length).toBe(32);
    });

    it("should serialize signature components to bytes", () => {
      const prvKey = 123456789n;
      const msg = [new Uint8Array([1, 2, 3])];
      const { randomizer, signature } = eddsaSign(prvKey, msg);

      const randomizerBytes = randomizer.toBytes();
      const signatureBytes = setLengthLeft(bigIntToBytes(signature), 32);

      expect(randomizerBytes).toBeInstanceOf(Uint8Array);
      expect(randomizerBytes.length).toBe(32);
      expect(signatureBytes).toBeInstanceOf(Uint8Array);
      expect(signatureBytes.length).toBe(32);
    });
      it("should serialize signature", () => {
          const prvKey = 123456789n;
          const msg = [new Uint8Array([1, 2, 3])];
          const { randomizer, signature } = eddsaSign(prvKey, msg);
          const pubKey = jubjub.Point.BASE.multiply(prvKey);
          const pubKeyBytes = pubKey.toBytes();
          const Rbytes = randomizer.toBytes();
          const signatureBytes = setLengthLeft(bigIntToBytes(signature), 32);

          const R = jubjub.Point.fromHex(bytesToHex(Rbytes));
          const publicKey = jubjub.Point.fromHex(bytesToHex(pubKeyBytes));
          let S = bytesToNumberBE(signatureBytes)
          const isValid = eddsaVerify(msg, publicKey, R, S);
          expect(isValid).toBe(true);

           expect(signatureBytes.length).toBe(32);

          console.log("R ", bytesToHex(Rbytes.reverse()))
          //big-endian
          console.log("Ry ",  randomizer.toAffine().y.toString(16))
      });
      it("verify signature", () => {
          let msg= "574968d8fd65d58c8aa51a4b51769548691c2db9d80535f6bb0078ff2ad79c42"
          let public_key= "433ff67b87411274686509c4cf9c44b74363885a3652ab4af91e145da426f602"
          let signature = "84d688d16f616c8c2eb479ecc500b0da294cab9bdf12b39268ac5d7f18e577c325edfc914d097ec8021678a0f890445e919e6167e05b829870af830431af5a01"


          let buf = Buffer.from(public_key, 'hex');
          const publicKey = jubjub.Point.fromBytes(buf);
          const R_hex = signature.slice(0, 64);
          const S_hex = signature.slice(64);
          buf = Buffer.from(R_hex, 'hex');
          const R = jubjub.Point.fromBytes(buf);

          const S_bytes = hexToBytes(S_hex);
          let S = bytesToNumberLE(S_bytes);
          const msgBytes = hexToBytes(msg);
          const isValid = eddsaVerify([msgBytes], publicKey, R, S);
          expect(isValid).toBe(true);

      });
  });
});
