import { eddsaVerify } from "../src/lib";
import {
    jubjub } from "@noble/curves/misc";
import {hexToBytes, bytesToNumberLE} from "@noble/curves/utils";

describe("verify rust signature", () => {
        it("verify rust signature", () => {
            let msg= "4ae1f4021ffcf18f1cce4bd18b819e970a2e06d8cd9794e9076b444972aad437"
            let public_key= "f665c0823d48ce22183b3a0cc19bc6eaa219d9f8523703add9cb65a863b07eb0"
            let signature = "4d4d74db1fca0babdb62092456e84dc48bea4f7bd1856e70e25035ecb18358bf98c2baf22828897eaaba7424bb907a27b33fb966ba97619c4f3ed8651dc3cb08"

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
