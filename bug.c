#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main()
{
	char buffer[10];
	read(0,buffer,256);
	return 0;
}