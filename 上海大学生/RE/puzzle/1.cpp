// ConsoleApplication3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include<iostream>
using namespace std;
bool __cdecl fun(int a1)
{
	int value1 = 138;
	int value2 = 417;
	int value3 = 298;

	int value4 = 617;
	int value5 = 521;
	int value6 = 104;
	int value7 = 927;
	int value8 = 712;
	bool result; // al
	//cout << value1 << value2 << value3 << value4 << endl;;
	int v1;
	v1 = a1;
	int count = 0;
	while (2)
	{
		switch (v1%10)
		{
		case 0:
			value3 &= value7;
			value4 *= value3;
			goto LABEL_4;
		case 1:
			if (!value4)
				goto LABEL_6;
			value3 /= value4;
			value2 += value6;
			goto LABEL_4;
		case 2:
			value5 ^= value6;
			value8 += value1;
			goto LABEL_4;
		case 3:
			value8 -= value5;
			value5 &= value2;
			goto LABEL_4;
		case 4:
			value6 *= value1;
			value4 -= value7;
			goto LABEL_4;
		case 5:
			value1 ^= value4;
			value7 -= value8;
			goto LABEL_4;
		case 6:
			if (!value8)
				goto LABEL_6;
			value6 |= value2 / value8;
			value2 /= value8;
			goto LABEL_4;
		case 7:
			value7 += value3;
			value6 |= value2;
			goto LABEL_4;
		case 8:
			value1 *= value4;
			value5 -= value8;
			goto LABEL_4;
		case 9:
			value3 += value6;
			value4 ^= value5;
		LABEL_4:
			v1 = v1 / 10;
			if (++count != 8)
				continue;
			result = (value7 == 231)
				+ (value6 == 14456)
				+ (value5 == 14961)
				+ (value4 == -13264)
				+ (value3 == 16)
				+ (value2 == 104)
				+ (value1 == -951) == 7;
			if (value8 != -239)
				goto LABEL_6;
			break;
		default:
		LABEL_6:
			result = 0;
			break;
		}
		return result;
	}
}

int  main()
{
	for (int i = 0; i < 999999999999; i++) {
			if (fun(i))
			cout << i << endl;
	}
	system("pause");
	return 0;
}
// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
