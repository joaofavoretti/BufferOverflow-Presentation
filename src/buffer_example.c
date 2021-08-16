#include <string.h>

void foo() {
	unsigned char buffer[500];    // Declara um buffer com 500 bytes

	memset(buffer, 0x41, 500);    // Seta todos os 500 bytes do buffer com a letra 'A' (ASCII 0x41)

	return;
}

int main() {
	foo();

	return 0;
}
