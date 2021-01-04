#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win()
{
	system("/bin/sh");
}
int main()
{
	char buffer[10];
	int cntr;
	scanf("%d", &cntr);
	if(cntr==1)
		read(0,buffer,256);
	else
		read(0,buffer,8);
	return 0; 
}