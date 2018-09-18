# TripleDoggy -- 基于clang static analyzer的源码漏洞检测工具
---


### 简介
[Clang static analyzer](https://clang-analyzer.llvm.org)是一个基于clang的c/c++/object-c源代码检测框架。它首先对源文件进行预处理然后使用符号执行遍历整个源文件。开发者们可以开发自己的插件通过hook的方式在符号执行过程中与框架进行交互。该框架提供了大量的api接口，开发者可以利用这些接口得到大量有用的信息来帮助发现潜在问题。 

目前我们实现的有三个chekcer，包括:
1. NewDereferenceChecker，用于检测空指针解引用漏洞
2. DoubleFreeChecker，用于检测doublefree,use-after-free,memroy leak漏洞
3. OverflowChecker，用于检测整形溢出漏洞


### 安装  
```
推荐安装环境：ubuntu 16.04 LTS x64
```
安装cmake及Z3
```
apt-get install cmake
git clone https://github.com/Z3Prover/z3.git ~/z3
cd z3
python scripts/mk_make.py
cd build
make
sudo make install
```
下载源码及编译
```
cd ~
mkdir clang
cd clang
git clone https://github.com/GoSSIP-SJTU/TripleDoggy.git ./llvm
mkdir build
cd build
cmake -G -DCMAKE_BUILD_TYPE=Release "Unix Makefiles" ../llvm
make
cd ..
```
### 使用
```
  #测试NewDereferenceChecker
  ./build/bin/clang -cc1-analyze-analyzer-checker=alpha.unix.NewDereference ./llvm/tripledoggy_test/nulldereference.c
  #测试DoubleFreeChecker
  ./build/bin/clang -cc1-analyze-analyzer-checker=alpha.unix.DoubleFree ./llvm/tripledoggy_test/doublefree.c
  #测试OverflowChecker
  ./build/bin/clang -cc1-analyze-analyzer-checker=alpha.unix.OverFlow ./llvm/tripledoggy_testoverflow.c
```

## NewDereferenceChecker

## 中文
基于clang此前已经开发的**DereferenceChecker**（空指针解引用）插件，我们设计了自己新的**NewDereferenceChecker**。
### 原理及算法

首先我们提出几点观点，即在源代码中指针最原始的来源途径，无关操作系统与底层架构：

1. **&**,取地址符，对局部变量或者对全局变量取地址。
2. **new**，c++中的new操作符。
3. 内存分配函数，如**malloc**。
4. 直接将整数类型转换为指针类型，如**int \*p = (int*)0**。
5. 现有指针的偏移，如**\*p = \*q + 1**。

我们收集了一些在2017年评分高于7.5的CVE，手动检查了他们最后得出一个结论，绝大部分的空指针解引用bug来源于未对内存分配的返回作校验。所以我们作出如下几点假设:

1. 在第1种情况，地址值不可以为null。
2. 在第2，3种情况，地址值可能为null，也是绝大数bug发生的地方。
3. 在第4种情况，开发者应该为这种不安全的代码负责。
4. 在第5种情况，代码的安全性依赖为源指针的来源。

注意在第一种情况中包括了这种形式，**return "abc"**，这等价于对一个全局变量取地址。两个别名变量的指针是相等的。如***p=*q**。

所以我们的算法如下：

1. 识别所有的内存分配函数。
2. 获得所有的内存分配函数与new操作符的返回值并加入集合A。
3. 在地址被访问或者被写入时插入hook函数。
4. 检查看被访问的地址是否是A中任何一个地址的子地址，如是则对该地址进行约束求解，如果为0则报告错误。

我们基于几点假设来识别内存分配函数：

1. 返回值必须为空/结构体/类指针。
2. 参数个数必须小于等于3。
3. 所有参数类型必须为整型。

注意这些只是经验总结，可能会发生改变。

### 测试结果

我们在8个CVE上进行测试并获得87%的检测率，对于每个CVE文件平均产生6个warning，我们甚至找到一个由于不正确初始化导致的空指针解引用bug，目前还未被报出来。对于一个未被检测出来的CVE，我们手工调试了该过程发现导致该错误的原因为符号执行的路径爆炸。

### 缺点

1. 内存分配函数检测准确率不高。
2. 在这种情况下。这是第4，5种情况的组合，目前检测不出来。 
3. 间接函数调用不能获得完整的调用流程图。
 
```
if (xxx)
   return "sdfsdf";
else
   return null;
```  

 
### TO DO：

1. NPL识别内存分配函数。




## ENGLISH  

Based on the pre-designed **DereferenceChecker** that has been developed by the clang project itself, we implement our **NewDereferenceChecker**.  

### Concept & Algorithm
Fist at all, we came up with the idea that *pointer* originally comes from five ways regardless of the operatins system and the low level architecture:
 
1. **&**, which means get the address of a variable,global or local.  
2. **new** operator in c++.  
3. memory allocate function, such as **malloc**.  
4. directly convert a int type to pointer, such as **int \*p = (int*)0**.  
5. offset to avalible pointer, such as **\*p = \*q + 1**.  

we collected several CVEs with score higher than 7.5 in 2017, inspected them and finally came to the conclusion that majority of bugs came from lack check of the return value of memory allocate function. so we made an assumption:  

1. in case 1, the address can **not** be null.
2. in case 2,3, the address can be null, from which most bugs come.
3. in case 4, the developer should be responsible for the unsafe code.
4. in case 5, the security of the code depend on the source of original pointer.

note that in case 1, it also includes such situation, **return "abc"**, which equals to retrieving address from global variable. Two alais are the same pointer, for example ***p=*q**.

So our algorithm is:

1. identify all the memory allocation function.
2. get the return value of all memory allocatin function and new operator, all the value make up a set A.
3. hook the location that pointers are load and store.
4. check to see if the pointer is the subreigon of one in A, if so, do contrain solver to see if the value can be null. if so, report a bug.


Here, we identify memory allocation function base on several assumption:

1. the return value must be a void/class/structure pointer.
2. the number of arguments must be less than 3.
3. the type of each arguments must be integer.

Note that these are empirical assumptions which can be changed in the future.

### Evaluation
We have tested the plugin in 8 CVEs with 87% rate of discovery of bugs. For each CVE, it generates average 6 warnings. We even found a bugs that can be caused by incorrect initialization of a structure which has not been reported. For the one that has not been discovered, we manually debug the process to see that it was because of the limited power of symbolic execution.

### Limitation

1. limited rate of identify memory allocate function
2. in following case, it was a combination of case 1 and 4, it can not be discovered yet. 
3. incomplete call graph in indirect call.

```
if (xxx)  
   return "sdfsdf";
else
   return null;
```  
 
### TO DO:

1. NPL identification of memory allocate function.


## DoubleFreeChecker

## 中文
Double free漏洞的成因顾名思义，就是指一块内存被重复的释放两次以上。Clang static analyzer中的自己实现的检测算法为通过hook对应的内存分配释放函数来记录一块内存的状态，当发现有释放同一块内存的操作时，报告漏洞。然而在实际使用的源文件中，情况要比描述的复杂，主要由以下两个情况导致：
1. 内存分配释放函数为该库自己实现或者经过封装后的标准库函数，仅仅使用标准库函数名称匹配并不能准确的识别所有的内存分配释放函数。
2. 某块内存可能是经过外部函数分配后，通过参数传入到该C文件中的某个顶层函数中，因此不能捕获到该块内存的形成位置，从而不能记录该内存的状态。  

基于以上两点，我们提出的double free，内存泄漏及USE AFTER FREE的分析方法为：基于此前我们使用的启发式的内存分配函数的识别方法识别出内存分配函数和释放函数。定义两个集合，分别为已经分配未释放的内存集合A，已释放的内存集合B。通过符号执行，分析遇到内存分配函数时将该内存记录到A中，分析遇到释放函数时，将该块内存记录到B集合中并且删除A中对应的内存（如果存在的话），再次遇到对该块内存的释放操作时报告漏洞。在符号dead时检测是否存在A集合中的元素，存在则报告内存泄漏。在访问内存数据 时，检测所在内存是否在B集合中，在则报告UAF漏洞。

## ENGLISH
double-free vulnerability,as its name said, means that the same memory being freed more than twice. The checker used to find such vulnerability which has been developed by clang project hooks the memory-related function to record the state of one memory region. when a freed memory is going to be freed, it reports a warning. Howeverk, in reality, things get more complicated. here are the two main reasons:

1. Third party library implements their own memory functions which can not be recognized by the checker.
2. A memory region is allocated outside the context  which can not be traced by the checker.

Based on the two reasons, we proposed our algorithm: we defined two set:A, record the allocated memory, B, record the freed memory.During the symbolic execution, we add the memory to A when it meets a alloc-function while add the memory to b when its meet a free-function. we report a double free vulnerability when it try to free a memory that has been added to B.


## IntegerOverflowChecker

## 中文
Integer Overflow的漏洞检测较为复杂，导致该种漏洞复杂的原因在于：
1. 算术运算溢出不一定导致溢出漏洞，即该程序所需要的即为溢出后的结果。
2. 源代码中添加的检测代码通常位于算术运算结果之后，因此不能在算术运算处报告漏洞，否则产生误报。
3. 整型溢出类型多样，包含无符号溢出有符号溢出，不同位数的溢出。
我们提出的Integer Overflow使用污点分析作为基础，具体的分析方法如下：
1. 在top frame函数的开始处，将全局变量，输入参数标记为污点源，并在接下来的分析中，将标准输入函数的输入数据和未被定义的函数的返回值，指针形参数标记为污点源。
2. 在进行算术运算(目前定义为加法，减法，乘法)时，检查左值或者右值是否被污染，如果其中一个值被污染，则根据运算的值的类型检查算术运算结果是否溢出，如果溢出则将运算结果的符号值及产生溢出的条件记录下来。
3. 符号执行行至数组索引访问操作或者内存分配函数时，检测参数(数组索引 ，内存分配函数的整形参数)是否包含在记录中，如果存在，则将该溢出条件取出，再次检查该条件是否满足，如果满足则报告溢出漏洞。


## ENGLISH

integeroverflow vulnerability is more complicated, the main reasons are:
1. integeroverflow may does not cause vulnerability.
2. the check code usually appears after the mathematic operation.
3. the types of integeroverflow are virious.

we use taint analysis to implements ours checker:

1. at the begining of top frame function, we mark all the input as the source of taint analysis.
2. when the symbolic execution meets a mathematic operation, it checks whether the l-value or r-value is tainted. if so, record the result value and the contion.
3. when it meets a array index operation or memory allocate function, it chceks whether its integer arguments are in the set we recorded. if so, we check to see if the condition can be satisified again, if satisfied, we report a warning.
