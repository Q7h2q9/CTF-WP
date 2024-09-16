#Week1

## BasePlus

die检测无异常，拖进ida查看

![image-20240916014534586](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409160145105.png)

![image-20240916014746402](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409160147449.png)

发现是对输入的字符串在Encode中进行加密，将结果与目标字符串进行比较。查看Encode，发现很像base64解密，只是换了表以及对加密后的字符串的每一位与0xE进行了异或再输出。

![image-20240916014847778](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409160148941.png)

``` 
Secret          db '/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC'
```

用脚本跑出异或前的字符串，然后base64换表解码

```python
b=[]
a="lvfzBiZiOw7<lhF8dDOfEbmI]i@bdcZfEc^z>aD!"
for i in a:
    c=14^ord(i)
    print(chr(c),end='')
'''
bxhtLgTgAy92bfH6jJAhKlcGSgNljmThKmPt0oJ/
'''
```

BaseCTF{BA5e_DEcoD1N6_sEcr3t}

###知识点：base64加密方式的代码实现

## Ez Xor

用die检查没问题，换ida细看

![image-20240916015840483](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409160158565.png)

![image-20240916015926130](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409160159272.png)

大概流程是对输入的字符串先检查长度是否为28，然后对字符串进行加密，最终与指定字符串检查，一样就输出"You are good!"

细看KeyStream和encrypt函数

发现KeyStream函数是用v4和28生成了密钥并存到v14处，encrypt函数利用得到的密钥对输入字符串进行加密

```c
__int64 __fastcall KeyStream(__int64 a1, __int64 a2, int a3)
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i < a3; ++i )
    *(_BYTE *)(a2 + i) = i ^ *(_BYTE *)(a1 + i % 3);
  return 1i64;
}
```

```c
__int64 __fastcall encrypt(__int64 a1, __int64 a2, int a3)
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i < a3; ++i )                    // 28
    *(_BYTE *)(a2 + i) ^= *(_BYTE *)(a3 - i - 1i64 + a1);
  return 1i64;
}
```

（省略目标字符串的寻找提取）逆向写出代码运行就拿到flag

```c
unsigned char v14[] =
{
	0x58, 0x6E, 0x70, 0x5B, 0x6B, 0x77, 0x5E, 0x68, 0x7A, 0x51, 
	0x65, 0x79, 0x54, 0x62, 0x7C, 0x57, 0x7F, 0x63, 0x4A, 0x7C, 
	0x66, 0x4D, 0x79, 0x65, 0x40, 0x76, 0x68, 0x43, 0x00, 0x00
};

unsigned char Str[] =
{
	0x01, 0x09, 0x05, 0x25, 0x26, 0x2D, 0x0B, 0x1D, 0x24, 0x7A, 
	0x31, 0x20, 0x1E, 0x49, 0x3D, 0x67, 0x4D, 0x50, 0x08, 0x25, 
	0x2E, 0x6E, 0x05, 0x34, 0x22, 0x40, 0x3B, 0x25, 0x00, 0x00
};
#include<stdio.h>
int main(){
	for(int i=0;i<28;i++){
		*(Str+i)^=*(28-i-1+v14);
	}
	printf("%s",Str);
	return 0;
}

//BaseCTF{X0R_I5_345Y_F0r_y0U}
```

## UPX mini

die查看

![image-20240916100745882](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161007013.png)

经典upx加壳，拿工具脱壳

![image-20240916100943805](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161009860.png)

![image-20240916101041154](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161010201.png)

再放到ida中分析，常规的base64加密后比较字符串

![image-20240916101413549](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161014605.png)

在线工具秒了

![image-20240916101631011](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161016051.png)

```
BaseCTF{Hav3_@_g0od_t1m3!!!}
```

## You are good at IDA

常规流程，然后拿ida分析

![image-20240916101828854](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161018888.png)

![image-20240916101900359](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161019392.png)

![image-20240916101944131](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161019154.png)

BaseCTF{Y0u_4Re_900d_47_id4}

### 知识点：ida常规操作

## ez_maze

看名字应该是迷宫题

![image-20240916102316499](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161023556.png)

分析一下拿到地图以及操作就是awsd分别表示左上下右

![image-20240916102549740](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161025780.png)

用py跑出地图原型，然后手动跑得到路径（没考虑最优解，不会深度广度搜索代码（(哭)，最后md5

![image-20240916102714040](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161027133.png)

```python
#sssssssddddwwwddsssssssdddsssddddd
#BaseCTF{131B7D6E60E8A34CB01801AE8DE07EFE}
```

### 知识点：迷宫题的分析，自动寻路（深度优先搜索、广度优先搜索）

# Week2

略（没认出Tea算法，心态爆炸，不想丸啦（）

# Week3

## ezAndroid

apk拿到雷电里打开

![image-20240916103645151](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161036189.png)

拿到jadx里面分析，搜索"Enter flag"字符串定位到关键代码

![image-20240916103723935](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161037986.png)

找到判断函数，看起来像是对输入的字符串进行base64加密然后与目标字符串比较，这里的目标字符串是从assets文件里的flag文件里读取的

![image-20240916103807098](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161038143.png)

找到flag并打开，发现不是base64编码后的字符串

![image-20240916104022660](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161040710.png)

重新分析Base64encode函数，发现这是一个自定义的

![image-20240916104112672](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161041698.png)

（不会，拷打ai）

![image-20240916104335878](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161043945.png)

![image-20240916104440065](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161044097.png)

不太懂，找找文件，发现了.so文件，ida拿去分析

![image-20240916104459609](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161044638.png)

定位到Base64encode函数，看不懂算法，浇给ai

![image-20240916104603132](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161046188.png)

![image-20240916104932782](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161049825.png)

应该是异或，拿c跑

```c
#include<stdio.h>
#include<string.h>
unsigned char ida_chars[] =
{
	0x61, 0x36, 0x62, 0x34, 0x64, 0x34, 0x66, 0x65, 0x33, 0x34, 
	0x36, 0x31
};

unsigned char hexData[48] = {
	0x23, 0x57, 0x11, 0x51, 0x27, 0x60, 0x20, 0x1E,
	0x72, 0x5A, 0x52, 0x43, 0x0E, 0x5F, 0x06, 0x6B,
	0x5C, 0x0D, 0x05, 0x04, 0x6C, 0x5D, 0x45, 0x6E,
	0x02, 0x04, 0x04, 0x57, 0x3B, 0x47, 0x09, 0x3A,
	0x55, 0x02, 0x02, 0x55, 0x3E, 0x50, 0x17, 0x5A,
	0x0A, 0x4D, 0x39, 0x51, 0x06, 0x50, 0x03, 0x4C 
};
char flag[48]={0};
int main(){
	
	for(int i=0;i<48;i++){
		flag[i]=hexData[i]^ida_chars[i%12];
	}
	printf("%s",flag);
	return 0;
}
```

```c
//BaseCTF{Android_89ca_is_c2fc_so_f64d_funny_45d5}
```

## 出题人已疯

![image-20240916105841799](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161058847.png)

die分析，好像是用c#写的，没学过，现场搜

![image-20240916105211947](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161052999.png)

找了一圈，感觉dnspy好一些，现下，然后把exe放到dnspy里分析

![image-20240916105323882](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161053938.png)

![image-20240916105429997](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161054112.png)

看不懂根本看不懂，只能一个一个的看，终于找到了

![image-20240916105907807](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161059854.png)

就是把输入的字符串的每一位进行异或操作，与目标字符串作比较

这里首先使用`string.Join`方法将`this.sentences`（假设是一个字符串列表或数组）连接成一个字符串，然后将其转换为字符数组

![image-20240916110133136](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161101171.png)

最后还是靠ai给代码（哭）

```python
import math

# 模拟 C# 中的 string.Join 和 ToCharArray
sentences = [
    "你以为我还会在乎吗？\ud83d\ude2c\ud83d\ude2c\ud83d\ude2c我在昆仑山练了六年的剑\ud83d\ude1f\ud83d\ude1f\ud83d\ude1f我的心早就和昆仑山的雪一样冷了\ud83d\ude10\ud83d\ude10\ud83d\ude10我在大润发杀了十年的鱼\ud83d\ude2b\ud83d\ude2b\ud83d\ude2b我以为我的心早已跟我的刀一样冷了\ud83d\ude29\ud83d\ude29\ud83d\ude29",
    "我早上坐公交滴卡的时候和司机大叔说“两个人”，司机惊讶地看着我“你明明就是一个人，为什么要滴两个人的卡？”我回他，“我心中还有一个叫Kengwang的。”司机回我说，“天使是不用收钱的。”",
    "（尖叫）（扭曲）（阴暗的爬行）（扭动）（阴暗地蠕动）（翻滚）（激烈地爬动）（痉挛）（嘶吼）（蠕动）（阴森的低吼）（爬行）（分裂）（走上岸）（扭曲的行走）（不分对象攻击）",
    "地球没我照样转？硬撑罢了！地球没我照样转？硬撑罢了！地球没我照样转？硬撑罢了！地球没我照样转？硬撑罢了！地球没我照样转？硬撑罢了！地球没我照样转？硬撑罢了！",
    "扭曲上勾拳！阴暗的下勾拳！尖叫左勾拳！右勾拳爬行！扭动扫堂腿！分裂回旋踢！这是蜘蛛阴暗的吃耳屎，这是龙卷风翻滚停车场！乌鸦痉挛！老鼠嘶吼！大象蠕动！愤怒的章鱼！无差别攻击！无差别攻击！无差别攻击！"
]

# 拼接所有句子
all_sentences = ''.join(sentences)

# 转换为字符数组
array2 = list(all_sentences)

# 定义一个函数来模拟 C# 中的逻辑
def process_input(input_text, array2):
    array = list(input_text)
    array2_len = len(array2)
    for i in range(len(array)):
        # 假设需要将 char 转为 int 进行运算
        array[i] = ord(array[i]) ^ i ^ ord(array2[i % array2_len])
        array[i] = chr(int(math.sqrt(array[i])))
    return array

# 预定义的源数组
source = [
    24164, 27173, 32145, 17867, 40533, 21647, 17418, 30032, 27950, 62998,
    60750, 64870, 52680, 61797, 49234, 59762, 16704, 19200, 32132, 24038,
    21764, 30130, 28113, 23070, 27413, 27917, 28938, 50207, 64834, 60132,
    64832, 63334, 55103, 22176, 21991, 20073, 22281, 19476, 28302, 24336,
    24720, 19544, 23018, 43976
]
chr_source = [chr(i) for i in source]

flag=process_input(chr_source,array2)
for i in flag:
    print(i,end='')
#BaseCTF{y0u_KnOw_UTF16_6uT_U_r_n0t_Cr@zym@n}
```

## 世界上最简单的题目

打开发现是python代码逆向，简单的干扰混淆，批量替换成易于识别的就好理解逻辑了

![image-20240916110645985](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161106073.png)

![image-20240916110756344](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161107468.png)

搓脚本解

```python

a1 =[1 ,1 ,1 ,3 ,1 ,1 ,1 ,3 ,1 ,1 ,1 ,3 ,1 ,1 ,3 ,1 ,1 ,3 ,1 ,1 ,3 ,1 ,3 ,1 ,3 ,1 ,3 ]#line:6#18个1
f1 =[101 ,102 ,117 ,120 ,119 ,108 ,102 ,124 ,100 ,109 ]#line:7

number1 =18 #line:29

number0 =9 #line:30
for i in range (26,-1,-1):#line:50
    
    if a1 [i]==1 :#line:51
        f1[number0 ]= (f1 [number0 ]^number1 )#line:57
        number1 -=1 #line:58
    elif a1 [i]==3 :#line:59
        number0 -=1 #line:60
flag=[]
for i in f1:
    flag.append(chr(i))

print("BaseCTF{"+''.join(flag)+"}")
#BaseCTF{easyvmvmvm}
```

# Week4

## BaseRE

常规分析

![image-20240916111551412](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161115466.png)

发现这里变红，问了big佬才知道这是花指令，现学吧

![image-20240916111657894](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161116947.png)

![image-20240916111832752](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161118828.png)

![image-20240916111858726](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161118841.png)

学了点回来继续看代码，发现总共要去除两处的花指令

第一处

![image-20240916111936763](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161119814.png)

![image-20240916112637682](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161126738.png)

第二处

![image-20240916112723453](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161127520.png)

![image-20240916112715090](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161127154.png)

查看反编译源码

![image-20240916112749164](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161127219.png)

感觉去花的时候把一些重要数据也nop了，猜测算法是对输入字符串进行base64加密最后与目标字符串比较，但又解不出来，想起之前去花第一处的代码还没用上，回去看看

![image-20240916113647939](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161136982.png)

原来是对码表进行了替换，搓脚本拿到替换后的码表，最后跑脚本解密

```c
#include<stdio.h>

unsigned char aAbcdefghijklmn[] =
{
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 
	0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 
	0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 
	0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 
	0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 
	0x79, 0x7A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
	0x38, 0x39, 0x2B, 0x2F, 0x00
};


int main(){
	
	int v3,v5;
	for (int i = 0; i < 64; ++i )
	{
		v3 = ((i >> 2) + 5 * i) % 64;
		if ( i != v3 )
		{
			v5 = aAbcdefghijklmn[i];
			aAbcdefghijklmn[i] = aAbcdefghijklmn[v3];
			aAbcdefghijklmn[v3] = v5;
		}
	}
	printf("%s",aAbcdefghijklmn);
	
}

```

![image-20240916113928944](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161139029.png)

## UPX PRO MAX

常规检查，发现是upx加壳，而且还改了点东西，放010看看

![image-20240916114038323](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161140371.png)

查看后发现标志位"UPX"没了，给它加上

![image-20240916114153777](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161141837.png)

![image-20240916114207780](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161142857.png)

然后正常脱壳，放ida里分析

![image-20240916114255752](https://cdn.jsdelivr.net/gh/quanfanghe/photohouse/picgoandgithub/202409161142801.png)

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int verify_str[43]; // [rsp+40h] [rbp-40h] BYREF
  unsigned int sub_7FF785[8]; // [rsp+F0h] [rbp+70h] BYREF
  unsigned int sub_7FF784[8]; // [rsp+110h] [rbp+90h] BYREF
  unsigned int sub_7FF783[8]; // [rsp+130h] [rbp+B0h] BYREF
  unsigned int sub_7FF782[8]; // [rsp+150h] [rbp+D0h] BYREF
  unsigned int sub_7FF781[8]; // [rsp+170h] [rbp+F0h] BYREF
  unsigned int sub_7FF780[8]; // [rsp+190h] [rbp+110h] BYREF
  char TAB[43]; // [rsp+1B0h] [rbp+130h] BYREF
  char Ctrl[43]; // [rsp+1E0h] [rbp+160h] BYREF
  int i2; // [rsp+214h] [rbp+194h]
  int i1; // [rsp+218h] [rbp+198h]
  int i0; // [rsp+21Ch] [rbp+19Ch]

  _main(argc, argv, envp);
  puts(
    "||   / |  / /                                                                           //   ) )                    "
    "         //   ) ) /__  ___/ //   / / ");
  puts(
    "||  /  | / /  ___     //  ___      ___      _   __      ___       __  ___  ___         //___/ /   ___      ___      "
    "___     //          / /    //___     ");
  puts(
    "|| / /||/ / //___) ) // //   ) ) //   ) ) // ) )  ) ) //___) )     / /   //   ) )     / __  (   //   ) ) ((   ) ) //"
    "___) ) //          / /    / ___      ");
  puts(
    "||/ / |  / //       // //       //   / / // / /  / / //           / /   //   / /     //    ) ) //   / /   \\ \\    /"
    "/       //          / /    //          ");
  puts(
    "|  /  | / ((____   // ((____   ((___/ / // / /  / / ((____       / /   ((___/ /     //____/ / ((___( ( //   ) ) ((__"
    "__   ((____/ /   / /    //           ");
  Sleep(0x1F4u);
  puts("At this point, Shell's learning comes to an end.");
  puts("I hope you enjoyed it.");
  puts("plz input your flag:");
  memset(sub_7FF780, 0, sizeof(sub_7FF780));
  memset(sub_7FF781, 0, sizeof(sub_7FF781));
  memset(sub_7FF782, 0, sizeof(sub_7FF782));
  memset(sub_7FF783, 0, sizeof(sub_7FF783));
  memset(sub_7FF784, 0, sizeof(sub_7FF784));
  memset(sub_7FF785, 0, sizeof(sub_7FF785));
  verify_str[42] = 0;
  verify_str[0] = 34;
  verify_str[1] = 17;
  verify_str[2] = 23;
  verify_str[3] = 33;
  verify_str[4] = 22;
  verify_str[5] = 17;
  verify_str[6] = 60;
  verify_str[7] = 61;
  verify_str[8] = 36;
  verify_str[9] = 16;
  verify_str[10] = 46;
  verify_str[11] = 82;
  verify_str[12] = 93;
  verify_str[13] = 41;
  verify_str[14] = 109;
  verify_str[15] = 114;
  verify_str[16] = 108;
  verify_str[17] = 14;
  verify_str[18] = 54;
  verify_str[19] = 52;
  verify_str[20] = 100;
  verify_str[21] = 66;
  verify_str[22] = 87;
  verify_str[23] = 78;
  verify_str[24] = 59;
  verify_str[25] = 36;
  verify_str[26] = 54;
  verify_str[27] = 58;
  verify_str[28] = 35;
  verify_str[29] = 101;
  verify_str[30] = 92;
  verify_str[31] = 46;
  verify_str[32] = 116;
  verify_str[33] = 124;
  verify_str[34] = 125;
  verify_str[35] = 44;
  verify_str[36] = 109;
  verify_str[37] = 67;
  verify_str[38] = 19;
  verify_str[39] = 122;
  verify_str[40] = 104;
  verify_str[41] = 17;
  scanf("%s", Ctrl);
  while ( i0 <= 6 )
  {
    if ( Ctrl[0] != 0x42
      || Ctrl[1] != 0x61
      || Ctrl[2] != 0x73
      || Ctrl[3] != 0x65
      || Ctrl[4] != 0x43
      || Ctrl[5] != 0x54
      || Ctrl[6] != 0x46 )
    {                                           // BaseCTF
      printf("wrong WRONG !!!");
      return -1;
    }
    ++i0;
  }
  for ( i1 = 0; i1 < strlen(Ctrl); ++i1 )
    TAB[i1] = Ctrl[41] ^ Ctrl[i1] ^ i1;
  for ( i2 = 0; i2 < strlen(Ctrl) - 1; ++i2 )
    TAB[i2] ^= TAB[i2 + 1];
  disorder(TAB, sub_7FF780, sub_7FF781, sub_7FF782, sub_7FF783, sub_7FF784, sub_7FF785);
  if ( verify(sub_7FF780, sub_7FF781, sub_7FF782, sub_7FF783, sub_7FF784, sub_7FF785, verify_str) )
    printf("GOOD GOOD !!!");
  return 0;
}
```

常规代码逆向，分析后搓脚本

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
unsigned int verify_str[43]; // [rsp+40h] [rbp-40h] BYREF
unsigned int sub_7FF785[8]; // [rsp+F0h] [rbp+70h] BYREF
unsigned int sub_7FF784[8]; // [rsp+110h] [rbp+90h] BYREF
unsigned int sub_7FF783[8]; // [rsp+130h] [rbp+B0h] BYREF
unsigned int sub_7FF782[8]; // [rsp+150h] [rbp+D0h] BYREF
unsigned int sub_7FF781[8]; // [rsp+170h] [rbp+F0h] BYREF
unsigned int sub_7FF780[8]; // [rsp+190h] [rbp+110h] BYREF
char TAB[43];
char Ctrl[43]={'\0'};
int main()
{
	verify_str[42] = 0;
	verify_str[0] = 34;
	verify_str[1] = 17;
	verify_str[2] = 23;
	verify_str[3] = 33;
	verify_str[4] = 22;
	verify_str[5] = 17;
	verify_str[6] = 60;
	verify_str[7] = 61;
	verify_str[8] = 36;
	verify_str[9] = 16;
	verify_str[10] = 46;
	verify_str[11] = 82;
	verify_str[12] = 93;
	verify_str[13] = 41;
	verify_str[14] = 109;
	verify_str[15] = 114;
	verify_str[16] = 108;
	verify_str[17] = 14;
	verify_str[18] = 54;
	verify_str[19] = 52;
	verify_str[20] = 100;
	verify_str[21] = 66;
	verify_str[22] = 87;
	verify_str[23] = 78;
	verify_str[24] = 59;
	verify_str[25] = 36;
	verify_str[26] = 54;
	verify_str[27] = 58;
	verify_str[28] = 35;
	verify_str[29] = 101;
	verify_str[30] = 92;
	verify_str[31] = 46;
	verify_str[32] = 116;
	verify_str[33] = 124;
	verify_str[34] = 125;
	verify_str[35] = 44;
	verify_str[36] = 109;
	verify_str[37] = 67;
	verify_str[38] = 19;
	verify_str[39] = 122;
	verify_str[40] = 104;
	verify_str[41] = 17;
	
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF780[j0] = (char)verify_str[j0];
		TAB[j0]=(char)sub_7FF780[j0];
	}
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF781[j0] = (char)verify_str[j0+7];
		TAB[j0+35]=(char)sub_7FF781[j0];
	}
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF782[j0] = (char)verify_str[j0+14];
		TAB[j0+14]=(char)sub_7FF782[j0];
	}
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF783[j0] = (char)verify_str[j0+21];
		TAB[j0+21]=(char)sub_7FF783[j0];
	}
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF784[j0] = (char)verify_str[j0+28];
		TAB[j0+7]=(char)sub_7FF784[j0];
	}
	for (int j0 = 0; j0 <= 6; ++j0 )
	{
		sub_7FF785[j0] = (char)verify_str[j0+35];
		TAB[j0+28]=(char)sub_7FF785[j0];
	}
	int len = 42;
	// 假设 Ctrl[41] 已知，或者根据实际情况推测
	char Ctrl_41 = '}';  // 示例值，根据实际情况修改
	
	// 第二步：逆向恢复 TAB[i2 + 1]
	for (int i2 = len - 2; i2 >= 0; --i2) {
		
		TAB[i2] = TAB[i2] ^ TAB[i2 + 1];
	}
	
	// 第一步：逆向生成 Ctrl
	for (int i1 = 0; i1 < len; ++i1) {
		Ctrl[i1] = TAB[i1] ^ Ctrl_41 ^ i1;
	}
	
	printf("%s",Ctrl);

	
	return 0;
}
//BaseCTF{W3lC0M3_2_ReV3r$e_xOr_1s_$O_e@S|!}
```

