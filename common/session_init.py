#设置全局url和请求头
import requests
import unittest
from loguru import logger
from configparser import ConfigParser
from common.handle_path import path_project
from configparser import ConfigParser
import os
import pytest

# class Session_init:
#     # 实例化一个session类
#     def setUp(self)->None:  #每次执行用例前都会执行
#         self.session=requests.session()
#         # 设置全局通用请求头
#         self.session.headers={"Content-Type":"application/json"}
#         #设置全局url,先要读取conf文件中的配置文件sql.ini,ConfigParser内置模块的ConfigParser().read('配置文件路径')
#         conf = ConfigParser()
#         conf.read(os.path.join(path_project, "conf", "server.ini"), encoding="utf-8")
#         self.base_url = conf.get("baseurl", "url")
#
#     def tearDown(self)->None:   #每次用例执行后执行
#         self.session.close()

#第二种方式执行前后置方式 ：@pytest.fixture()
class session_init:
    @pytest.fixture(scope="function",autouse=True)
    def Session_req(self):
        self.session = requests.session()
        self.session.headers = {"Content-Type":"application/json"}

    def Resp(self,base_url,url,params,headers):
        res=self.session.post(base_url+url,params=params,headers=self.session.headers)

    def Session_close(self):
        self.session.close()
