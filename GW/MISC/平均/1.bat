@echo 开始注册
copy dll %windir%\system32\
regsvr32 %windir%\system32\dll /s
@echo dll注册成功
@pause