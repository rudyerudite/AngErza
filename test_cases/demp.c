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

void inc_rax()
{
	asm("inc %rax;ret;");
}

void pop_rax()
{
  asm("pop %rax;ret");
}

void sys_call()
{
  asm("syscall");
}

void xor_rax()
{
	asm("xor %rax, %rax;ret;");
}

int main()
{
	char buf[10];
	printf("Let's do it!");
	gets(buf);
	return 0;
}
