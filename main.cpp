/*
 * main.cpp
 *
 *  Created on: Nov 19, 2013
 *      Author: ms88
 *
 *  This is a simple test for RELIC RSA and ECDH features on an X86_64 platform
 */
#include <stdio.h>
extern "C" {
#include <relic.h>
}
#include <stdlib.h>

int main() {

	core_init(); //Necessary to allocate all memory
	//Testing RSA encryption/decryption and signature/verification with PKCS1.5
	rsa_t pub, prv;
	unsigned char in[10], out[BN_BITS / 8 + 1];
	int il, ol;
	int result;

	rsa_null(pub);rsa_null(prv);

	rsa_new(pub);
	rsa_new(prv);

	result = cp_rsa_gen_quick(pub, prv, BN_BITS);

	if (result == STS_OK)
		printf("RSA Key generation was fine\n");
	il = 10;
	ol = BN_BITS / 8 + 1;
	rand_bytes(in, il);

	if (cp_rsa_enc(out, &ol, in, il, pub) == STS_OK)
		printf("RSA Encryption was OK\n");

	if (cp_rsa_dec_quick(out, &ol, out, ol, prv) == STS_OK)
		printf("RSA Decryption was OK\n");

	if (memcmp(in, out, ol) == 0)
		printf("RSA Decryption after Encryption was OK\n");

	il = 10;
	ol = BN_BITS / 8 + 1;
	rand_bytes(in, il);

	if (cp_rsa_sig_quick(out, &ol, in, il, 0, prv) == STS_OK)
		printf("RSA Signing was OK\n");

	if (cp_rsa_ver(out, ol, in, il, 0, pub) == 1)
		printf("RSA Verification was OK\n");

	//Testing ECDH key exchanged with NIST_P256 curve
	bn_t d_a, d_b;
	ec_t q_a, q_b;
	unsigned char key[MD_LEN], key1[MD_LEN], key2[MD_LEN];
	ep_param_set(NIST_P256);
	bn_null(d_a);bn_null(d_b);ec_null(q_a);ec_null(q_b);
	bn_new(d_a);
	bn_new(d_b);
	ec_new(q_a);ec_new(q_b);
	cp_ecdh_gen(d_a, q_a);
	cp_ecdh_gen(d_b, q_b);

	cp_ecdh_key(key1, MD_LEN, d_b, q_a);
	cp_ecdh_key(key2, MD_LEN, d_a, q_b);

	if (memcmp(key1, key2, MD_LEN) == 0)
		printf("ECDH key generation with Prime curve was OK\n");

	core_clean();

	printf("---------------------------------------------------\n");

}
