#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_alg.h>
#include <sys/socket.h>

int main() {
	int fd, ret;
	struct sockaddr_alg alg;

	fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		printf("No AF_ALG support\n");
		exit(1);
	}

	printf("AF_ALG supported\n");

	alg.salg_family = AF_ALG;
	sprintf((char *)alg.salg_type, "aead");
	alg.salg_feat = 2;
	alg.salg_mask = 42;
	sprintf((char *)alg.salg_name, "authencesn(hmac(sha256),cbc(aes))");

	ret = bind(fd, (struct sockaddr *)&alg, sizeof(alg));

	if (ret < 0) {
		close(fd);
		exit(2);
	}

	printf("bind succeeded surprisingly!\n");
	close(fd);
	return 0;
}

