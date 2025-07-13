package main

// https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos_test.go
import (
	"crypto/rand"
	"fmt"

	"encoding/hex"
)

func binaryFieldMul(A []byte, B []byte) []byte {
	// multiplies `A` and `B` in the finite field of order 2^256.
	// The reference is Hankerson, Vanstone and Menezes, Guide to Elliptic Curve Cryptography. https://link.springer.com/book/10.1007/b97644
	// `A` and `B` are both assumed to be 32-bytes slices. here we view them as little-endian coordinate representations of degree-255 polynomials.
	// the multiplication takes place modulo the irreducible (over F_2) polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1. see Table A.1.
	// the techniques we use are given in section 2.3, Binary field arithmetic.
	// for the multiplication part, we use Algorithm 2.34, "Right-to-left comb method for polynomial multiplication".
	// for the reduction part, we use a variant of the idea of Figure 2.9, customized to our setting.
	const W = 64             // the machine word width, in bits.
	const t = 4              // the number of words needed to represent a polynomial.
	c := make([]uint64, 2*t) // result
	a := make([]uint64, t)
	b := make([]uint64, t+1)  // will hold a copy of b, shifted by some amount
	for i := 0; i < 32; i++ { // "condense" `A` and `B` into word-vectors, instead of byte-vectors
		a[i>>3] |= uint64(A[i]) << (i & 0x07 << 3)
		b[i>>3] |= uint64(B[i]) << (i & 0x07 << 3)
	}
	for k := 0; k < W; k++ {
		for j := 0; j < t; j++ {
			// conditionally add a copy of (the appropriately shifted) B to C, depending on the appropriate bit of A
			// do this in constant-time; i.e., independent of A.
			// technically, in each time we call this, the right-hand argument is a public datum,
			// so we could arrange things so that it's _not_ constant-time, but the variable-time stuff always depends on something public.
			// better to just be safe here though and make it constant-time anyway.
			mask := -(a[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFFFFFFFFFFFFFFF else 0x0000000000000000
			for i := 0; i < t+1; i++ {
				c[j+i] ^= b[i] & mask // conditionally add B to C{j}
			}
		}
		for i := t; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// multiplication complete; begin reduction.
	// things become actually somewhat simpler in our case, because the degree of the polynomial is a multiple of the word size
	// the technique to come up with the numbers below comes essentially from going through the exact same process as on page 54,
	// but with the polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1 above instead, and with parameters m = 256, W = 64, t = 4.
	// the idea is exactly as described informally on that page, even though this particular polynomial isn't explicitly treated.
	for i := 2*t - 1; i >= t; i-- {
		c[i-4] ^= c[i] << 10
		c[i-3] ^= c[i] >> 54
		c[i-4] ^= c[i] << 5
		c[i-3] ^= c[i] >> 59
		c[i-4] ^= c[i] << 2
		c[i-3] ^= c[i] >> 62
		c[i-4] ^= c[i]
	}
	C := make([]byte, 32)
	for i := 0; i < 32; i++ {
		C[i] = byte(c[i>>3] >> (i & 0x07 << 3)) // truncate word to byte
	}
	return C
}

// Dummy placeholder for binaryFieldMul — replace with actual GF(2^n) implementation
//func binaryFieldMul(a, b []byte) []byte {
//    result := make([]byte, len(a))
// naive example: byte-by-byte AND (not actual field multiplication!)
//    for i := 0; i < len(a); i++ {
//        result[i] = a[i] & b[i]
//    }
//    return result
//}

/*
	binary arithmatic multiplication

to constrain the range of values, we perform the multiplication over a finite field by performing a modulo of an
irreducible polynomial of f(X)=X²⁵⁶+X¹⁰+X⁵+X²+1. This is the equivalent to performing a (mod p) operation within
integer operations. For multiplication of two 2,048 bit values (256 bytes):
multiplying a value by itself 256 times. Little Fermat's theory: a^p(modp)=a
*/
func main() {

	fmt.Println("=====================================")
	fmt.Println("🧪 Little Endian Multiplication Tests")
	fmt.Println("=====================================")

	d1, _ := hex.DecodeString("0300000000000000000000000000000000000000000000000000000000000000")
	d2, _ := hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")

	d3 := binaryFieldMul(d1, d2)

	fmt.Printf("\nInput 1 (3):      %x\n", d1)
	fmt.Printf("Input 2 (5):      %x\n", d2)
	fmt.Printf("Result (3 * 5):   %x\n", d3)

	temp := make([]byte, 32)
	_, _ = rand.Read(temp)

	expected := make([]byte, 32)
	copy(expected, temp) // initial random
	count := 0
	for j := 0; j < 256; j++ {

		temp = binaryFieldMul(temp, temp)
		fmt.Printf("[%x...] ", temp[:3])
		count = count + 1

	}
	fmt.Printf("Multiplications: %d\n", count)
	fmt.Printf("\n\nFinal: %x\n", temp)
	fmt.Printf("Expected: %x\n", expected)

}

/*
% go run main.go


3= 0300000000000000000000000000000000000000000000000000000000000000
5= 0500000000000000000000000000000000000000000000000000000000000000
3 times 5= 0f00000000000000000000000000000000000000000000000000000000000000
[79b2e0...] [737ec0...] [8c5e2f...] [946767...] [388113...] [eb2eb6...] [08381c...] [c9fa1a...] [3916d4...] [cfee25...] [02f2c3...] [d06cf2...] [fb9949...] [8c176b...] [84190d...] [bb9a0a...] [ee8f04...] [31dddb...] [79533b...] [416026...] [51671f...] [740707...] [89f4d8...] [983c8c...] [3f63c8...] [9122e2...] [e0f627...] [2f2413...] [c131f5...] [0150c5...] [aa9ac6...] [7b5a82...] [9c1c7f...] [5d95ec...] [aaec47...] [d781c8...] [c16da5...] [bd3103...] [fd5aec...] [41ef2d...] [a7ff70...] [a9c4e0...] [29f8e0...] [ed9f72...] [390902...] [7eba1c...] [9ab7cc...] [8d8785...] [51503b...] [0bf1a6...] [4fd59d...] [157c99...] [33a54a...] [452980...] [fa2228...] [7c6f57...] [b6270d...] [3b001d...] [67840e...] [677685...] [9c3a07...] [4d5af2...] [79c0cd...] [636566...] [671820...] [fe766b...] [af8db7...] [453a4f...] [41c604...] [7482bc...] [1744b2...] [e30d2a...] [c1f739...] [4ca828...] [cea0ca...] [04a3f5...] [d4d6af...] [229bea...] [f8cd49...] [83d20d...] [e9b70f...] [82d3b8...] [af5efd...] [183847...] [07a8fa...] [a4a5a5...] [50bc89...] [6fd952...] [8cfccd...] [fcdbe6...] [eb65b1...] [b36d41...] [37eaa2...] [7a19cb...] [dab590...] [902d78...] [de2ca6...] [7cd15f...] [bb772a...] [3a02a5...] [7bea8f...] [91eda2...] [ba441b...] [f81178...] [ab02c4...] [778e7e...] [f466e1...] [eb4971...] [60b1a6...] [62f913...] [7cb3a2...] [99d3e0...] [2e6811...] [6beb6a...] [eeceff...] [d71e4b...] [520942...] [97e1a3...] [d187c5...] [063538...] [c7dca6...] [0f8ea1...] [3dac7b...] [2e3707...] [26537e...] [3140bd...] [8fdb1b...] [f4be1b...] [fc9725...] [d4bfb1...] [755c54...] [c5d8a9...] [0caa01...] [477ffe...] [67a689...] [3764f6...] [8c5578...] [7f3073...] [187908...] [fc91ff...] [5d0547...] [8f6cbd...] [f9ae95...] [3e27bb...] [5e9004...] [efc087...] [969320...] [cd7d44...] [fd0f31...] [29d726...] [fd4076...] [df9b50...] [20a685...] [3f2f9d...] [8b0dff...] [270cfd...] [8c3165...] [d9aa84...] [697031...] [ed2e7d...] [692eff...] [56bf16...] [211e78...] [337f9b...] [9671ec...] [36e53e...] [7c481d...] [62cfd0...] [4ed8a6...] [f23bd6...] [491c9d...] [4c65f3...] [653a89...] [168185...] [7c4cac...] [1728fa...] [1265b9...] [c0f21e...] [005004...] [993510...] [985890...] [7f9b84...] [d14ec0...] [954161...] [a72102...] [707ccb...] [acce0e...] [8eed50...] [ff8ad5...] [e32539...] [02e4d4...] [af5eb1...] [8b9816...] [6a557f...] [e5aa82...] [b70a00...] [b30b3e...] [e403ef...] [9e5e47...] [af1d99...] [be87d4...] [f5abe1...] [299e6e...] [29191a...] [981de5...] [b60da6...] [0e1f7f...] [66ef9a...] [61c670...] [1bcaf5...] [ee3af8...] [e8a123...] [ac42ad...] [2ff22d...] [c1e5f8...] [115b6c...] [63bcc1...] [8cdb55...] [0096d1...] [578766...] [f9b629...] [0cedd1...] [b62296...] [03dba8...] [cbd73a...] [b4fc50...] [4ab715...] [66553c...] [c04d6c...] [5a87d4...] [ca2e3d...] [61f58f...] [3e6f8a...] [b8b232...] [deb503...] [c710b7...] [e938d7...] [0c3848...] [5711af...] [7a78c8...] [c77aea...] [a9a5b7...] [3e43a8...] [bfc604...] [15ed0a...] [29ca4f...] [9279ac...] [87fad7...] [425343...] [9d84bb...] [1b2c68...] [dc6496...] [c4c5fa...] [9e9e64...] [90c71d...] [b1d15e...] Multiplications: 256


Final: b1d15e9edf59adda7e3f482d754d6af533cb11269087efb14419c6e1c4cba4b4
Expected: b1d15e9edf59adda7e3f482d754d6af533cb11269087efb14419c6e1c4cba4b4
(base) chanfamily@Chans-Air trial_tmp % go run main.go
=====================================
🧪 Little Endian Multiplication Tests
=====================================

Input 1 (3):      0300000000000000000000000000000000000000000000000000000000000000
Input 2 (5):      0500000000000000000000000000000000000000000000000000000000000000
Result (3 * 5):   0f00000000000000000000000000000000000000000000000000000000000000
[64efb8...] [0abf26...] [d7a0f5...] [700c43...] [0db4ea...] [82084f...] [e5d296...] [6ec739...] [e27492...] [19db22...] [ba3874...] [04c8ce...] [32d188...] [a86f8f...] [b69cd7...] [e82d13...] [991d56...] [df3589...] [4fdfb2...] [42deeb...] [9a0105...] [498593...] [34b7b6...] [62274d...] [53627a...] [b3c036...] [a9ce88...] [46702b...] [da038c...] [aff7a8...] [e935fd...] [6425e6...] [38d493...] [17f701...] [8b4073...] [6004f8...] [62086a...] [590692...] [c5ab26...] [b0cbe7...] [bb2552...] [201852...] [bb245e...] [3d5382...] [342d10...] [075fbf...] [159481...] [464255...] [3c90ba...] [8ed9a3...] [43fb58...] [fe4c79...] [3b2c73...] [c63a19...] [2c9b4a...] [b1d64e...] [6e9dec...] [dabf1c...] [26c941...] [ddd23b...] [463e31...] [61e7f1...] [c56385...] [92bb45...] [5966d8...] [fda41f...] [ea8453...] [8046f8...] [68c99e...] [2fdcb2...] [ccb54b...] [321c5c...] [97213f...] [815174...] [3e4e58...] [8a99ae...] [e85f5d...] [d9f5d1...] [3e16f1...] [e864a7...] [1a6217...] [b8d836...] [28cc5e...] [28cd07...] [f16593...] [69e925...] [c28a07...] [0900a3...] [ea6b2a...] [769e0a...] [901ec3...] [251582...] [fde385...] [164dab...] [f8d3ff...] [b6e85e...] [f8a265...] [1a16c1...] [a807b3...] [b6b9d3...] [a551e0...] [5698fd...] [f2a7e2...] [2b35dd...] [c10f86...] [e76289...] [3ab0e2...] [0ebc54...] [d7eb25...] [b9dacd...] [d8a4ec...] [8e5203...] [04e377...] [62578f...] [c74710...] [2a4e07...] [da6043...] [90589e...] [28d171...] [787e8f...] [b1a9fb...] [06f5a1...] [4437b6...] [84d4bd...] [07fb7c...] [3a819b...] [d754c9...] [4f52cc...] [525118...] [4e19f0...] [b232e3...] [1e6a19...] [3b38ea...] [8172b5...] [95b1e3...] [516d80...] [636843...] [c1235d...] [e056a6...] [10befb...] [bce44d...] [655aa2...] [a7853f...] [4592a0...] [2e0ee7...] [d0db0e...] [7ff777...] [f42fa8...] [c9c80b...] [ba5c5b...] [033812...] [ae5e10...] [d04fb6...] [c90374...] [c59fa5...] [41e3e9...] [c5f3b0...] [9f5a47...] [8b49db...] [e31eb4...] [8c3a0e...] [ec9037...] [651b11...] [6ed7be...] [7b8571...] [be2cc1...] [f24b73...] [0e80d9...] [bf2217...] [601aef...] [25d4c2...] [cf1ca1...] [a9780a...] [013822...] [adbe66...] [6e5af7...] [135cf8...] [ae6a2a...] [3c593f...] [22b3b8...] [f23d30...] [2b00a3...] [1f9308...] [81088b...] [644d11...] [103155...] [d36cb2...] [42495f...] [f5c952...] [4c8315...] [47ebb4...] [8c352b...] [7f706a...] [cb6169...] [20ecc0...] [386ee0...] [4714eb...] [f36274...] [9b6195...] [60e4ef...] [6fe91d...] [12ad51...] [c7860d...] [77d88f...] [c689cb...] [1425d3...] [9e1b6d...] [144804...] [de0226...] [f21fba...] [765219...] [f242d5...] [bf10e6...] [d6be7e...] [14a0cd...] [e6c9ec...] [31d4de...] [6408a0...] [9e3b82...] [66cb36...] [3cd426...] [9e0697...] [491a4a...] [dfd5ed...] [15f9ae...] [69229c...] [8f576b...] [6a6b08...] [9a79e2...] [14d7e9...] [d4a27d...] [78ad79...] [35a298...] [1b9081...] [425047...] [d06c98...] [c386af...] [be2018...] [ff6e63...] [08d367...] [00f8f8...] [bc6167...] [6f4b58...] [4fbf53...] [8c9de1...] [d3fb03...] [b31452...] [e926df...] [2409b6...] [99ae7c...] [edff72...] [0b93db...] [48843f...] [578e68...] [aef5cc...] [ddcb89...] Multiplications: 256


Final: ddcb897a938fcb985800ec4215dcd9f1be07b9d01867a4bdd1d31203ae178a1b
Expected: ddcb897a938fcb985800ec4215dcd9f1be07b9d01867a4bdd1d31203ae178a1b
*/