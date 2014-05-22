/*
 * Copyright (c) 2014 Jay Schulist <jayschulist@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "baseX.h"

#define PUBLIC_KEY_SIZE	65
#define BTC_BIN_ADDR_SIZE 25

enum prompts {
	BTC_ADDR,
	BTC_SIG
};

static char *
get_bitcoin_info(pam_handle_t * pamh, int type)
{
	struct pam_message message;
	const struct pam_message * pmessage = &message;
  	char *msg = NULL;
  	int len;

  	/* build up the message we're prompting for */
  	message.msg = NULL;
  	message.msg_style = PAM_PROMPT_ECHO_ON;

  	switch (type) {
    	case BTC_ADDR:
      		message.msg = "bitcoin address: ";
      		break;

    	case BTC_SIG:
      		message.msg = "signature: ";
      		break;
  	}

  	struct pam_conv *conv = NULL;
  	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
    		return NULL;
  	}

  	struct pam_response *responses = NULL;
  	if (conv->conv(1, &pmessage, &responses, conv->appdata_ptr) != PAM_SUCCESS || responses == NULL) {
    		return NULL;
  	}

  	char * promptval = responses->resp;
  	free(responses);

  	/* If we didn't get anything, just move on */
  	if (promptval == NULL) {
    		return NULL;
  	}

	/* Note: must free message when done. */
  	msg = malloc(PAM_MAX_MSG_SIZE);
  	memset(msg, '\0', PAM_MAX_MSG_SIZE);
  	len = strlen(promptval);
  	if (len > PAM_MAX_MSG_SIZE)
    		len = PAM_MAX_MSG_SIZE;
  	memcpy(msg, promptval, len);

  	// printf("%s\n", promptval);
  	free(promptval);
  	return msg;
}

/* base58 so we don't want 0OIl characters. */
static int
base58_check(char *data, int len)
{
	const char base58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	int base58_len = strlen(base58);
	int i, j;

  	for (i=0; i < len; i++) { // check all base58 for a match
		for (j=0; j < base58_len; j++) {
			if (data[i] == base58[j])
          			break;
    		}
    		if (j == base58_len)  // no match found character not base58
			return -EINVAL;
	}
	return 0;
}

/* returns: malloc string, caller must free. */
static char *
remove_whitespace(char *str)
{
	char *i, *result;
        int temp = 0;

	if (str == NULL)
		return NULL;

	result = malloc(strlen(str)+1);
	memset(result, 0, strlen(str)+1);
        for (i = str; *i; ++i) {
		if (!isspace(*i)) {
                	result[temp] = (*i);
                	++temp;
            	}
	}
        result[temp] = '\0';
        return result;
}

/* returns: malloc string, caller must free. */
static char * 
verify_access(pam_handle_t *pamh, const char *file, char *addr)
{
	char *address, *username = NULL;
	char data[1000];
	FILE *fd;
	char delims[] = ",";

	/* If no configuration then ignore, so defaults work. */
	fd = fopen(file, "r");
	if (fd < 0) {
		pam_syslog(pamh, LOG_ERR, "Unable to open configuration file: %s", file);
		return NULL;
  	}

	/* comments start with '#'
	 * one per line, format: bitcoin-address, username 
	 */
	while (fgets(data, 1000, fd) != NULL) {
		/* remove comments. */
		if (data[0] == '#')
			continue;
		/* remove any whitespace */
		address = remove_whitespace(strtok(data, delims));
		if (address == NULL)
			continue;
		username = remove_whitespace(strtok(NULL, delims));
                if (username == NULL) {
			free(address);
                        continue;
		}
		if (!strcmp(addr, address)) {
			free(address);
			break;
		}
		free(username);
		username = NULL;
	}
  	fclose(fd);
	return username;
}

/* Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
 * recid selects which key is recovered
 * if check is non-zero, additional checks are performed
 *
 * Original source of this code from bitcoin-qt client.
 *
 * Copyright (c) 2009-2013 Bitcoin Developers
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */
static int
ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, 
	const unsigned char *msg, int msglen, int recid, int check)
{
    	if (!eckey) return 0;

    	int ret = 0;
    	BN_CTX *ctx = NULL;

    	BIGNUM *x = NULL;
    	BIGNUM *e = NULL;
    	BIGNUM *order = NULL;
    	BIGNUM *sor = NULL;
    	BIGNUM *eor = NULL;
    	BIGNUM *field = NULL;
    	EC_POINT *R = NULL;
    	EC_POINT *O = NULL;
    	EC_POINT *Q = NULL;
    	BIGNUM *rr = NULL;
    	BIGNUM *zero = NULL;
    	int n = 0;
    	int i = recid / 2;

    	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    	if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    	BN_CTX_start(ctx);
    	order = BN_CTX_get(ctx);
    	if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    	x = BN_CTX_get(ctx);
    	if (!BN_copy(x, order)) { ret=-1; goto err; }
    	if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    	if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    	field = BN_CTX_get(ctx);
    	if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    	if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    	if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    	if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    	if (check) {
        	if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        	if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        	if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    	}
    	if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    	n = EC_GROUP_get_degree(group);
    	e = BN_CTX_get(ctx);
    	if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    	if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    	zero = BN_CTX_get(ctx);
    	if (!BN_zero(zero)) { ret=-1; goto err; }
    	if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    	rr = BN_CTX_get(ctx);
    	if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    	sor = BN_CTX_get(ctx);
    	if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    	eor = BN_CTX_get(ctx);
    	if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    	if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    	if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    	ret = 1;

err:
    	if (ctx) {
        	BN_CTX_end(ctx);
        	BN_CTX_free(ctx);
    	}
    	if (R != NULL) EC_POINT_free(R);
    	if (O != NULL) EC_POINT_free(O);
    	if (Q != NULL) EC_POINT_free(Q);
    	return ret;
}

#if 0
// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
static int 
variable_uint_size(uint64_t i)
{
    if (i < 0xfd)
        return 1;
    else if (i <= 0xffff)
        return 3;
    else if (i <= 0xffffffff)
        return 5;
    else
        return 9;
}
#endif

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
static int
dbl_hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data_in, data_in_len);
	SHA256_Final(hash1, &ctx);
	SHA256(hash1, sizeof(hash1), data_out);
	/*
	printf("dbl_hash256(hex): ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                printf("%02x", data_out[i]);
        printf("\n");
	*/
	return 0;
}

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
static int
hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	SHA256(data_in, data_in_len, data_out);
	return 0;
}

/* returns a string of length RIPEMD160_DIGEST_LENGTH in data_out */
static int
hash160(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	RIPEMD160_CTX ctx;

	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, data_in, data_in_len);
	RIPEMD160_Final(data_out, &ctx);
	return 0;
}

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
static int
msg2hash256(unsigned char *msg_s, int msg_len, unsigned char *data_out)
{
        const char magic[] = "Bitcoin Signed Message:\n";
	int magic_len = strlen(magic);
        unsigned char *msg_b;
        int len;

	/* allocate var_int + msg + var_int + msg */
        msg_b = malloc(1 + magic_len + 1 + msg_len);
	if (!msg_b)
		return -1;

	/* add the magic... */
	len = 0;
        msg_b[len] = magic_len;
        len++;
        memcpy(&msg_b[len], magic, magic_len);
        len += magic_len;

	// FIXME: use variable_uint_size() for messages longer than 253 bytes
	if (msg_len > 253) {
		free(msg_b);
		return -2;
	}

	/* add the message... */
        msg_b[len] = msg_len;
	len++;
        memcpy(&msg_b[len], msg_s, msg_len);
        len += msg_len;

	dbl_hash256(msg_b, len, data_out);
        free(msg_b);
	return 0;
}

/* returns non-NULL bitcoin address upon success and sets addr_len to length. */
static unsigned char *
pubkey2address(EC_KEY *pubkey, int *addr_len, int compressed)
{
	unsigned char ripemd_b[RIPEMD160_DIGEST_LENGTH];
	unsigned char checksum[SHA256_DIGEST_LENGTH];
	unsigned char bin_addr[BTC_BIN_ADDR_SIZE];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *address, *addr, *addr2;
	int retval, pubkey_len;

	/* get public key as a binary string: 65 bytes uncompressed, 33 bytes compressed. */
	EC_KEY_set_conv_form(pubkey, compressed
		? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
        pubkey_len = i2o_ECPublicKey(pubkey, NULL);
	if (pubkey_len != PUBLIC_KEY_SIZE) {
		*addr_len = -1;
		return NULL;
	}
	addr = malloc(pubkey_len);
	if (!addr) {
		*addr_len = -2;
		return NULL;
	}
	addr2 = addr;
        retval = i2o_ECPublicKey(pubkey, &addr2);
	if (retval != pubkey_len) {
		*addr_len = -3;
		free(addr);
		return NULL;
	}

	/* use the recovered pubkey to reconstruct bitcoin address. */
	hash256(addr, pubkey_len, hash);
	hash160(hash, sizeof(hash), ripemd_b);
	bin_addr[0] = 0x00;     // Network ID Byte
        memcpy(&bin_addr[1], ripemd_b, sizeof(ripemd_b));
	retval = dbl_hash256(bin_addr, 21, checksum);
	memcpy(&bin_addr[21], &checksum[0], 4);
	address = b58_encode(bin_addr, sizeof(bin_addr), addr_len);
	free(addr);
	return address;
}

/* returns 1 upon success (pubkey is recovered and signature verified)
 * otherwise < 0 for error. 
 */
static int
verified_pubkey_recovery(EC_KEY *key, ECDSA_SIG *sig, 
	unsigned char *sig_bin, int sig_bin_len, unsigned char *hash, int hash_len)
{
	unsigned char *p64;
        int retval, rec;

	/* The first byte is the recovery parameter plus 27. 
         * If the corresponding public key is to be a compressed one,
         * 4 is added. The next 32 bytes encode r. The last 32 bytes encode s.
         */
        rec = (sig_bin[0] - 27) & ~4;
        p64 = &sig_bin[1];
        if (rec < 0 || rec >= 3)
                return -1;
        BN_bin2bn(&p64[0],  32, sig->r);
        BN_bin2bn(&p64[32], 32, sig->s);
        // printf("(sig->r, sig->s): (%s,%s)\n", BN_bn2hex(sig->r), BN_bn2hex(sig->s));
        retval = ECDSA_SIG_recover_key_GFp(key, sig, hash, hash_len, rec, 0);
        if (retval <= 0)
                return -2;

        /* verify message, signature, and public key. */
        retval = ECDSA_do_verify(hash, hash_len, sig, key);
        if (retval <= 0)
		retval = -3;

	return retval;
}

/* verify the signature of a message. 
 * first recover the public key, then verifying the signature using message and public key, 
 * finally rebuild the bitcoin address and compare it to the address provided.
 *
 * returns 1 upon successful verification, 0 unsuccessful, < 0 for errors.
 */
static int
verify_signature(pam_handle_t *pamh, char *addr_s, char *msg_s, char *sign_s)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char sign_b[PUBLIC_KEY_SIZE];
	unsigned char *address;
	ECDSA_SIG *sig = NULL;
	EC_KEY *key = NULL;
	int retval, addr_len, msg_len, sign_len;

	addr_len = strlen(addr_s);
	msg_len  = strlen(msg_s);
	sign_len = strlen(sign_s);

	/*
	printf("verify_signature:\n  '%s' %d\n  '%s' %d\n  '%s' %d\n",
		msg_s, msg_len, sign_s, sign_len, addr_s, addr_len);
	*/

	/* decode signature string into 65 byte binary array. */
        retval = b64_decode((uint8_t *)sign_s, sign_len, sign_b);
	if (retval != PUBLIC_KEY_SIZE) {
		pam_syslog(pamh, LOG_ERR, "signature failed to decode base64, bad len: %d", retval);
		return -1;
	}

	/* double sha256 hash of message, using electrum signature format. */
	retval = msg2hash256((unsigned char *)msg_s, msg_len, hash);
	if (retval < 0) {
		pam_syslog(pamh, LOG_ERR, "message failed to hash: too long > 253");
		return -2;
	} 

	/* use recovered public key from signature to verify message. */
	sig = ECDSA_SIG_new();
	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	retval = verified_pubkey_recovery(key, sig, sign_b, sizeof(sign_b), hash, sizeof(hash));
	if (retval < 0) {
		pam_syslog(pamh, LOG_ERR, "failed pubkey recovery or verification: retval=%d", retval);
		retval = -3;
		goto err;
	}

	/* create bitcoin address from public key and compare for final verifcation. */
        address = pubkey2address(key, &retval, 0);
	if (address == NULL) {
		pam_syslog(pamh, LOG_ERR, "unable to build address from public key (retval=%d)\n", retval);
		retval = -4;
		goto err;
	}
	if ((retval == addr_len)
		&& !memcmp(addr_s, address, addr_len))
		retval = 1;
	else
		retval = 0;
	free(address);
err:
	ECDSA_SIG_free(sig);
	EC_KEY_free(key);
	return retval;
}

/* verify_address: check address length, base58check, and checksum.
 * returns 1 upon success, 0 bad checksum, <0 error 
 */
static int
verify_address(char *addr_s)
{
        unsigned char *bin_addr, checksum[SHA256_DIGEST_LENGTH];
        int addr_len, bin_addr_len;
	int retval;

	/* check length and base58 encoding. */
	if (!addr_s)
		return -1;
        addr_len = strlen(addr_s);
        if (addr_len < 27 || addr_len > 34)
                return -2;
        if (base58_check(addr_s, addr_len) < 0)
                return -3;

	/* decode from base58 to 25 byte binary array. */
        bin_addr = b58_decode((unsigned char *)addr_s, addr_len, &bin_addr_len);
        if (!bin_addr)
                return -4;
        if (bin_addr_len != BTC_BIN_ADDR_SIZE) {
		retval = -5;
		goto err;
        }

	/* check version byte. */
	if ((bin_addr[0] != 0) && (bin_addr[0] != 111)) {
		retval = -6;
		goto err;
	}

	/* compute address checksum and compare. */
        dbl_hash256(bin_addr, 21, checksum);
        if (!memcmp(&bin_addr[bin_addr_len-4], checksum, 4))
                retval = 1;
        else
		retval = 0;

err:	free(bin_addr);
        return retval;
}

#if 0
    entropy = str(os.urandom(32)) + str(random.randrange(2**256)) + str(int(time.time())**7)
#endif

/* generate a random nonce, default nonce_len = 16. */
static unsigned char *
generate_nonce(pam_handle_t *pamh, int nonce_len)
{
	unsigned char *key, hash[SHA256_DIGEST_LENGTH];
	unsigned char *data_out;
	int randfd;
	int i, count, key_size = 32;

	/* open the random device to get key data. */
        randfd = open("/dev/urandom", O_RDONLY);
        if (randfd == -1) {
                pam_syslog(pamh, LOG_ERR, "Cannot open /dev/urandom: %m");
           	return NULL;
	}

	/* Read random data for use as the key. */
        key = malloc(key_size);
        if (!key) {
                close(randfd);
                return NULL;
        }
	count = 0;
        while (count < key_size) {
                i = read(randfd, key + count, key_size - count);
                if ((i == 0) || (i == -1)) {
                        break;
                }
                count += i;
        }
        close(randfd); 

	// FIXME: add random() + timestamp

	hash256(key, key_size, hash);
	free(key);
	data_out = malloc(nonce_len);
	if (!data_out)
		return NULL;
	memcpy(data_out, hash, nonce_len);
	return data_out;
}

/* FIXME: option for bitid uri challenge generation.
 * bitid://hostname/callback?x=Nonce&u=1 
 */
static char * 
challenge(pam_handle_t *pamh, int *out_len)
{
	unsigned char *nonce;
	char *msg;
	int i, len, msg_len;

	nonce = generate_nonce(pamh, 16);
	if (!nonce) {
		*out_len = -1;
		return NULL;
	}

	msg_len = (16 + 1) * 2;
	msg = malloc(msg_len);
	if (!msg) {
		*out_len = -2;
		free(nonce);
		return NULL;
	}
	memset(msg, '\0', msg_len);

	len = 0;
	for(i = 0; i < 16; i++)
		len += sprintf(msg + len, "%02x", nonce[i]);
	free(nonce);

	printf("challenge message: %s\n", msg);
	*out_len = strlen(msg);
	return msg;
}

static int
pam_bitcoin(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char *username = NULL, *addr = NULL, *message = NULL, *sig = NULL;
	const char *file = NULL;
  	int retval;

  	/* use filename for bitcoin username lookup. */
  	for (; argc-- > 0; ++argv) {
      		if (!strncmp (*argv, "file=", 5))
			file = (5 + *argv);
  	}

  	/* No file= option, must have it.  */
  	if (file == NULL || file[0] == '\0') {
    		pam_syslog(pamh, LOG_ERR, "bitid access configuration file path not provided");
    		retval = PAM_IGNORE;
		goto end;
  	}

  	/* get bitcoin address. */
  	addr = get_bitcoin_info(pamh, BTC_ADDR);
	if (addr == NULL) {
    		retval = PAM_USER_UNKNOWN;
		goto end;
  	}

  	/* validate address format provided from the user. */
	retval = verify_address(addr);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "malformed bitcoin address used for login: error %d", retval);
		retval = PAM_USER_UNKNOWN;
		goto end;
	}

	/* lookup address to see if user can login using bitcoin. */
	username = verify_access(pamh, file, addr);
	if (!username) {
		pam_syslog(pamh, LOG_ERR, "bitcoin address is not authorized for access: %s", addr);
		retval = PAM_USER_UNKNOWN; // PAM_AUTH_ERR;
		goto end;
	}

  	/* generate challenge message to sign. */
	message = challenge(pamh, &retval);
	if (!message || (retval < 0)) {
    		retval = PAM_USER_UNKNOWN;
		goto end;
  	}

  	/* get signature of message. */
  	if ((sig = get_bitcoin_info(pamh, BTC_SIG)) == NULL) {
    		retval = PAM_USER_UNKNOWN;
		goto end;
	}

  	/* use signature to recover and authenticate address. */
	retval = verify_signature(pamh, addr, message, sig);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "user: %s failed login signature verification from: %s\n", username, addr);
		retval = PAM_USER_UNKNOWN;
		goto end;
	}

	/* set username details associated with this address. */
        retval = pam_set_item(pamh, PAM_USER, username);
        if (retval != PAM_SUCCESS)
                goto end;
	pam_syslog(pamh, LOG_INFO, "user: %s allowed access from: %s\n", username, addr);

end:
	if (addr)
		free(addr);
	if (message)
		free(message);
	if (sig)
  		free(sig);
	return retval;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	return pam_bitcoin (pamh, flags, argc, argv);
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
	return PAM_IGNORE;
}

/* changing authentication token, could be used to update bitcoin address
 * user is allowed to login from.
 */
int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_bitcoin_modstruct = {
	"pam_bitid",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};

#endif
