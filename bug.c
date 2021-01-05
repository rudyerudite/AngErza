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
	char cntr[8]="";
		read(0,buffer,256);
	if(cntr== "appples")
		win();
	return 0; 
}