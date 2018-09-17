
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

// 同一个函数内的双重释放
int main()
{
    int n;
    char *p = NULL;
    scanf("%d", &n);
    p = (char*)malloc(n);
    free(p);
    free(p);
    return 0;
}

