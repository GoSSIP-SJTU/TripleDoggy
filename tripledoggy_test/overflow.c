
// scanf 函数输入的值，未经过检查直接相加的结构用于内存分配函数导致溢出
char* test(int a, int b)
{
    char* p ;
    int c = 0;
    c = a + b;
    p = malloc(c);
    return p;
}
