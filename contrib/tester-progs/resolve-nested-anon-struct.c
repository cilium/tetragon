#include <stdio.h>
#include <stdint.h>

struct anothernestedstruct {
	char *first;
	int second;
};

struct nestedstruct {
	int someint;
	struct {
		char achar;
	};
	struct {
		uint32_t someuint;
		struct {
			char * charp;
			struct {
				int first;
				struct anothernestedstruct ans;
				struct anothernestedstruct *pans;
			};
		};
	};
};


struct mystruct {
	int someint;
	struct {
		int anotherint;
		struct {
			int anothernestedint;
			struct nestedstruct nested;
			struct nestedstruct *pnested;
		};
	};
};



void passit(struct mystruct *s) {
	printf("%d,%d\n", s->nested.ans.second, s->pnested->pans->second);
}


int main(int argc, char **argv) {
	struct mystruct mys;
	mys.nested.ans.second = 7;
	struct nestedstruct myns;
	struct anothernestedstruct myans;
	mys.pnested = &myns;
	myns.pans = &myans;
	myans.second = 77;
	passit(&mys);
}
