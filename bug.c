#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
void win()
{
	system("/bin/sh");
}
int main()
{
	
	char buffer[10];
	char cntr[20]="";
	read(0,buffer,256);
	if(strcmp(cntr,"apples"))
		printf("lol");
	else if(strcmp(cntr,"pyramid"))
		win();
		//win();
	return 0; 
}