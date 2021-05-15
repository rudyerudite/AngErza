#include <stdio.h>
#include <alloca.h>
#include <unistd.h>
#include <stdlib.h>

void mov()
{
	asm("mov %rax, 0x0(%rdi);ret;");
}


void pop_rdi()
{
  asm("pop %rdi;ret");
}

void pop_rdx()
{
  asm("pop %rdx;ret");
}

void pop_rsi()
{
  asm("pop %rsi;ret");
}

void pop_rax()
{
  asm("pop %rax;ret");
}

void sys_call()
{
  asm("syscall");
}

void win(){
    system("/bin/sh");
}

int main()
{
	char buf[10];
	printf("Let's do it!");
	gets(buf);
	return 0;
}
