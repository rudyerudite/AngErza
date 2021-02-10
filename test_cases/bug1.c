#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void win()
{
	system("/bin/sh");
}

int main(int argc, char const *argv[])
{
	char a[10]="";
	char b[30];
	fgets(b,30,stdin);
	strcpy(a,b);

	return 0;
}
