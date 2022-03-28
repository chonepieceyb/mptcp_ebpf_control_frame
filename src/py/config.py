#-*- coding:utf-8 -*-
from yaml import load, SafeLoader
from common import BASE_CONFIG_PATH

def dict2obj(d):
    top = type('new', (object,), d)
    seqs = tuple, list, set, frozenset
    for i, j in d.items():
        if isinstance(j, dict):
            setattr(top, i, dict2obj(j))
        elif isinstance(j, seqs):
            setattr(top, i, 
                type(j)(dict2obj(sj) if isinstance(sj, dict) else sj for sj in j))
        else:
            setattr(top, i, j)
    return top

class Config : 
    @classmethod
    def config(cls): 
        with open(BASE_CONFIG_PATH, 'r', encoding = "utf-8") as f: 
            cfg_str = f.read()
            cls.cfg= dict2obj(load(cfg_str, Loader = SafeLoader))

def read_config():
    with open(BASE_CONFIG_PATH, 'r', encoding = "utf-8") as f: 
        cfg_str = f.read()
        return dict2obj(load(cfg_str, Loader = SafeLoader))        

CONFIG = read_config()

# test 
if __name__ == '__main__' : 
    print(type(CONFIG.mptcp_connects.max_entries))