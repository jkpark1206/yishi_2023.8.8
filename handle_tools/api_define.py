import jsonpath
import requests
from configparser import ConfigParser
import os
from handle_tools.handle_path import path_project
from loguru import logger

class APIDefine:
    #初始化方法
    def __init__(self):
        #读取.ini文件的内容
        conf = ConfigParser()
        #定位server.ini文件路径
        api_path = os.path.join(path_project,'conf','server.ini')
        #使用read()方法读取文件内容
        conf.read(api_path,encoding='utf-8')
        logger.info(f"与数据库进行连接操作，连接信息为:\n{conf.items()}")


    # def get_dl_token(self,session,data):
    #     res = session.post(, json=data)
    #     token = jsonpath.jsonpath(res.json(), '$.data.AuthToken')[0]
    #     return token



APIDefine()

