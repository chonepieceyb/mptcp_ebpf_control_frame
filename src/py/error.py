#-*- coding:utf-8 -*-
import os 

class LinuxError(Exception):
    def __init__(self, hint, errno):
        super().__init__(self) #初始化父类
        self.errorinfo= "%s, linux err: %d, %s"%(hint, errno, os.strerror(errno))
        self.errno = errno

    def __str__(self):
        return self.errorinfo

