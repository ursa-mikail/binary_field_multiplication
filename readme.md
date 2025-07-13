# 🔢 GF(2^256) Binary Field Multiplication in Go

This Go program implements multiplication over the binary finite field **GF(2²⁵⁶)**, using the irreducible polynomial:

implements binary field multiplication over GF(2^256) using a polynomial reduction method based on the irreducible polynomial $$\ 𝑓 ( 𝑋 ) = 𝑋^256 + 𝑋^10 + 𝑋^5 + 𝑋^2 + 1  \$$.


The implementation is inspired by the techniques described in _"Guide to Elliptic Curve Cryptography"_ by Hankerson, Vanstone, and Menezes. It uses:

- **Little-endian representation** for 256-bit numbers.
- **Right-to-left comb method** for polynomial multiplication (Algorithm 2.34).
- A tailored **modular reduction** step (based on Figure 2.9) using the specific irreducible polynomial.

---

## 📦 Structure

### `binaryFieldMul(A, B []byte) []byte`

This function takes two 32-byte slices `A` and `B` and returns their product in GF(2^256) after reduction.

### `main()`

The main function:
1. Demonstrates a multiplication test (`3 × 5`) using little-endian format.
2. Performs 256 self-multiplications of a randomly generated 256-bit value.
3. Displays the first few bytes of each intermediate multiplication step.

---

## 🧪 Sample Output

=====================================
🧪 Little Endian Multiplication Tests
Input 1 (3): 0300000000000000000000000000000000000000000000000000000000000000
Input 2 (5): 0500000000000000000000000000000000000000000000000000000000000000
Result (3 * 5): 0f00000000000000000000000000000000000000000000000000000000000000

[5c3...] [36e...] ...
Multiplications: 256

Final: 0cc7fc91c87a5d5e4c7b8ba7f9810b0eaa1e1f1db53ae8ee0d91c5c4bb27edcb
Expected: 0cc7fc91c87a5d5e4c7b8ba7f9810b0eaa1e1f1db53ae8ee0d91c5c4bb27edcb



---

## 🧠 Conceptual Notes

- Binary field arithmetic is useful in **cryptography**, especially **elliptic curve operations**.
- The field GF(2^n) is defined using polynomials over GF(2), modulo an **irreducible polynomial**.
- This implementation ensures multiplication is constant-time with respect to secret data to avoid side-channel leaks.

---

## 📚 References

- Hankerson, Vanstone, Menezes — *Guide to Elliptic Curve Cryptography*  
  [Springer Link](https://link.springer.com/book/10.1007/b97644)
- [Coinbase Kryptology: KOS Test Reference](https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos_test.go)

---

## 🚀 Run It

```bash
go run main.go

🔐 Security Notes
The multiplication is done in constant time relative to the secret input to avoid timing side-channel attacks.

Always validate cryptographic implementations before using them in production environments.

