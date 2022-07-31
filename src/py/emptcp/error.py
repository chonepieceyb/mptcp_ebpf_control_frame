#-*- coding:utf-8 -*-
import os 

class LinuxError(Exception):
    def __init__(self, hint, errno):
        super().__init__(self) #初始化父类
        self.errorinfo= "%s, linux err: %d, %s"%(hint, errno, os.strerror(errno))
        self.errno = errno

    def __str__(self):
        return self.errorinfo

class BPFLoadError(Exception):
    def __init__(self, hint):
        super().__init__(self)
        self.errorinfo = "BPFLoadError : %s"%hint 

    def __str__(self):
        return self.errorinfo

class BPFPinObjNotFound(BPFLoadError):
    def __init__(self, path):
        super().__init__("bpf pin obj: %s not found"%path)

class BPFPinObjExist(BPFLoadError):
    def __init__(self, path):
        super().__init__("bpf pin obj : %s exists"%path)

if __name__ == '__main__':
    raise BPFPinObjNotFound("./test_path")