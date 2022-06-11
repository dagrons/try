# 项目结构

- feature

    包含各种特征的提取方式，使用visitor pattern实现

- fetch

    指定sha256，从服务器上下载对应样本，返回bytes对象

- manipulate 

    针对bytes执行各种操作，返回操作完成后的bytes对象

- exps

    包含各种实验，不一定都有用

- scripts

    直接执行的脚本

- output

    程序编译或执行的产物

