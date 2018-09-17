
#include<stdio.h>
#include<stdlib.h>

// 最简单的可能导致空指针解引用的情况 1
int main()
{
	int n = 0;
	scanf("%d", &n);
	char *p = malloc(n);
	p[0] = 'a';
    return 0;
}

