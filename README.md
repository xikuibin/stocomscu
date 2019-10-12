
## 概述
stocomscu是一个Storage Commitment SCU的demo。使用方法请参考[stocomscu.md](stocomscu.md)。

## 编译


#### 依赖

目前的版本基于dcmtk 3.6.4，只在windows/visual studio 2015条件下进行了测试。

#### 编译

1. 下载解压dcmtk3.6.4的源代码包
2. 把dcmnet\apps目录下的stocomscu.cc和CMakeLists.txt拷贝到dcmtk源代码同名目录中
3. 按照编译dcmtk方法编译整个dcmtk包。stocomscu会和其他dcmnet提供的app生成到同一个目录。

#### 测试
使用Dvtk Storage SCP Emulator 5.0作为SCP

## 其他说明

原始代码参考了storescp/storescu编写，只保留了最基本功能。如果希望支持更多选项，可以参考原示例代码。



- 
