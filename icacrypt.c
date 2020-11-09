/*
 * icacrypt.c by cenobyte 2007
 *
 * Crypt stdin to a Citrix ICA password hash. You can use this to add a
 * password to an ICA file for a user during login (intercept the user password
 * via PAM) for "SSO" purposes in a hybrid Linux Gnome and Citrix environment.
 *
 * format in hex:
 * byte 01: [0x00]
 * byte 02: [password len + 1]
 * byte 03: [salt]
 * byte 04: [password[0] xor_eq (salt bit_or 0x43)]
 * byte 06: [password[i++] xor_eq password[i--] xor_eq salt ]
 * byte 07: [password[i++] xor_eq password[i--] xor_eq salt ]
 * etc
 *
 * Run:
 * $ echo helloworld | ./icacrypt 
 * 000b6d70f0e0f0d17150a0b02
 * 
 * Citrix xor borrowed from Dug Song's icadecrypt.c
 *
 */

#include <sys/types.h>

#include <netinet/in.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	u_char password[32];
	u_char salt = 0x6d; /* 0x96 */
	size_t last = 0;
	int len;
	int i;

	fgets(password, sizeof(password), stdin);
	last = strlen(password) - 1;
	if (password[last] == '\n')
		password[last] = '\0';

	len = last;
	
	/* password length check not implemented
	 */
	printf("000%x%x", len + 1, salt);

	password[0] ^= (salt | 0x43);
	printf("%x", password[0]);

	for(i=1; i < len; i++) {
		password[i] ^= password[i - 1] ^= salt;
		if (password[i] < 0x10)
			printf("0");

		printf("%x", password[i]);
	}

	printf("\n");

	return(0);
}
