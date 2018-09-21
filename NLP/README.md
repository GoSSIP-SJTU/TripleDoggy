## parser.py
此python文件为包含函数分词、语法分析、词法分析、语义分析以及敏感函数判断的程序文件。

使用方法为`./parser.py test.list`，附录材料中的test.list为测试所使用的函数名所在文件。

执行程序之后等待程序运行结束，会输出敏感函数名到test.list_sensitive.list文件中。

其中会包含所有分析所得的函数方法名称。


## standford
此目录中的两个jar包是stanford自然语言处理工具，因为此工具官方并没有提供python接口，仅仅提供了jar文件，所以需要nltk提供依赖分析的接口，如果此目录位置变更，则需要在parser.py文件中的`initiate()`函数中分别更改如下两个环境变量的路径。
``` python
os.environ["STANFORD_MODELS"]
os.environ["STANFORD_PARSER"]
```
[Stanford Models](http://central.maven.org/maven2/edu/stanford/nlp/stanford-parser/3.9.1/)

[Stanford Parser](http://central.maven.org/maven2/edu/stanford/nlp/stanford-parser/3.9.1/stanford-parser-3.9.1.jar)
