# 环境配置

系统 ： Windows 10 \ Linux kali 4.6.0-kali1-amd64  
程序 ： easyGo.easyGo  
要求 ： 输入口令  
使用工具 ：ida \ [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)  

# 开始分析
## 识别函数
将程序拖入ida中，根据字符串窗口的字串，可知这是一个go程序。接着使用IDAGolangHelper工具识别函数。在菜单栏选择`File`->`Script File`，然后选中IDAGolangHelper-master文件夹中的go_entry.py，弹出的窗口中每个按钮都试一下，然后单击`OK`。  

## 主函数
在左边的函数列表窗口中搜索到main函数：
```c 
__int64 __fastcall main_main(__int64 a1, __int64 a2)
{
  __int64 v2; // r8
  __int64 v3; // rdx
  __int64 result; // rax
  __int64 v5; // ST08_8
  __int64 v6; // rdx
  __int64 v7; // r8
  __int64 v8; // r8
  __int64 v9; // r8
  __int64 *v10; // [rsp-F8h] [rbp-F8h]
  __int64 v11; // [rsp-80h] [rbp-80h]
  signed __int64 v12; // [rsp-68h] [rbp-68h]
  __int64 *v13; // [rsp-60h] [rbp-60h]
  void *v14; // [rsp-58h] [rbp-58h]
  void **v15; // [rsp-50h] [rbp-50h]
  void *v16; // [rsp-48h] [rbp-48h]
  void **v17; // [rsp-40h] [rbp-40h]
  void *v18; // [rsp-38h] [rbp-38h]
  signed __int64 v19; // [rsp-30h] [rbp-30h]
  void *v20; // [rsp-28h] [rbp-28h]
  __int64 *v21; // [rsp-20h] [rbp-20h]
  void *v22; // [rsp-18h] [rbp-18h]
  void **v23; // [rsp-10h] [rbp-10h]

  while ( (unsigned __int64)&v11 <= *(_QWORD *)(__readfsqword(0xFFFFFFF8) + 16) )
    runtime_morestack_noctxt(a1, a2);
  runtime_newobject_autogen_540059(a1);
  v13 = v10;
  v22 = &MEMORY[0x4A6D00];
  v23 = &off_4E1130;
  fmt_Fprintln_autogen_NKFB74(a1, a2, &v22, &MEMORY[0x4A6D00], v2);
  v20 = &MEMORY[0x4A3E80];
  v21 = v13;
  fmt_Fscanf_autogen_IY3IV5(a1, a2, &off_4E2880);
  runtime_stringtoslicebyte_autogen_ZNPIZK(a1, a2, v3);
  runtime_slicebytetostring_autogen_UPL0LR(a1, a2, 2LL);
  encoding_base64__ptr_Encoding_DecodeString(a1);
  v12 = 1LL;
  MEMORY[0x19](a1);
  runtime_convTstring_autogen_PCT0SB(a1, a2);
  v18 = &MEMORY[0x4A6D00];
  v19 = 1LL;
  fmt_Fprintln_autogen_NKFB74(a1, a2, &off_4E28A0, &MEMORY[0x4A6D00], v8);
  if ( (void **)v13[1] == &v20 )
  {
    v5 = *v13;
    runtime_memequal(a1, a2, v12);
    v16 = &MEMORY[0x4A6D00];
    v17 = &off_4E1140;
    result = fmt_Fprintln_autogen_NKFB74(a1, a2, v6, &off_4E28A0, v7);
  }
  else
  {
    v14 = &MEMORY[0x4A6D00];
    v15 = &off_4E1150;
    result = fmt_Fprintln_autogen_NKFB74(a1, a2, v12, &off_4E28A0, v9);
  }
  return result;
}
```
主体流程不复杂，但go语言逆向涉及的比较少，所以这里还是使用了远程调试的方法，查看flag验证的逻辑。

## 远程调试
在kali机器上部署好环境，然后在地址`.text:0000000000495277 `处下断，输入数据后断下，单步不步入进行跟踪，发现主要流程是这样的：
```order
1. fmt_Fscanf_autogen_IY3IV5(a1, a2, &off_4E2880);
2. encoding_base64__ptr_Encoding_DecodeString(a1);
3. if ( (void **)v13[1] == &v20 )
```
在程序中，进行了base64解码操作后，直接就进行了判断，看来所有的流程就在`encoding_base64__ptr_Encoding_DecodeString`函数上了。  
但使用在线base64解码会发现，无法解码`tGRBtXMZgD6ZhalBtCUTgWgZfnkTgqoNsnAVsmUYsGtCt9pEtDEYsql3`。

这里，再观察调用`encoding_base64__ptr_Encoding_DecodeString`时压入的参数：
```asm
.text:00000000004952DD                 mov     [rsp], rax
.text:00000000004952E1                 mov     [rsp+8], rcx
.text:00000000004952E6                 mov     [rsp+10h], rdx
.text:00000000004952EB                 call    encoding_base64__ptr_Encoding_DecodeString ; encoding_base64__ptr_Encoding_DecodeString
```

存在三个参数，一个是编码后的数据，一个是数据的长度，还有一个呢？内容为`6789_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345`。

# 逻辑推理
第三个可疑的的参数看上去像一张表，而且编码后的数据看上去也不寻常。可能是采用了魔改后的base64进行编码。我们只需要还原算法，将数据解码出来就可以得到flag。

# 编写程序
按照以上逻辑，编写如下python代码：
```python
import string
import base64
my_base64table = "6789_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
std_base64table ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
s = "tGRBtXMZgD6ZhalBtCUTgWgZfnkTgqoNsnAVsmUYsGtCt9pEtDEYsql3"
s = s.translate(string.maketrans(my_base64table,std_base64table))
print base64.b64decode(s)
```

# 夺旗成功
输入计算得到的flag，提示成功：
```console
./easyGo.easyGo 
Please input you flag like flag{123} to judge:
flag{92094daf-33c9-431e-a85a-8bfbd5df98ad}
Congratulation the flag you input is correct!
```

# 参考链接
1. 无符号Golang程序逆向方法解析 [https://www.anquanke.com/post/id/170332](https://www.anquanke.com/post/id/170332)  
2. golang base64加密与解密 [https://studygolang.com/articles/6926](https://studygolang.com/articles/6926)  
3. MIPS架构的CTF逆向题--SUCTFbabyre题目writeup [https://blog.csdn.net/xiangshangbashaonian/article/details/83146678](https://blog.csdn.net/xiangshangbashaonian/article/details/83146678)