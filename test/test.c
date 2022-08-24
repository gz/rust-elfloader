// gcc -o test.x86_64 test.c -fPIC -fPIE
// gcc -o test_nopie.x86_64 test.c -no-pie
// aarch64-linux-gnu-gcc -o test.aarch64 test.c -fPIC -fPIE
// aarch64-linux-gnu-gcc -o test_nopie.aarch64 test.c -no-pie
#include <stdio.h>
int main( int argc, const char* argv[] )
{
	for( int i = 0; i < argc; i++ )
	{
		printf( "arg %d: %s\n", i, argv[i] );
	}
}