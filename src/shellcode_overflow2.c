#include <string.h>
#include <stdio.h>

void foo(char *string) {
	char buffer[500];
	
	strcpy(buffer, string);
}

int main(int argc, char **argv) {
	foo(argv[1]);

	return 0;
}

