from configparser import ConfigParser
from handle_tools.handle_path import path_project
import requests
import os
import json

class Session_req:
    def __init__(self):
        # 实例化一个session类
        self.session=requests.session()
        # 设置全局通用请求头
        self.session.header= {"Content-Type":"application/json"}
        # 设置全局URL,先读取ini文件中的数据,os.path.join(path_project,"conf","server.ini")将路径连接起来
        conf=ConfigParser()
        conf.read(os.path.join(path_project,"conf","server.ini"),encoding="utf-8")
        self.base_url=conf.get("baseurl","url")   #yaml读取方式，获取baseurl下的url的值
    #封装请求方法
    def send_req(self,method:str,url:str,data=None,token=None,**kwargs):
        self.__header(token)

        if method.upper() == "GET":
            resp = self.session.get(url,params=data,**kwargs)
        else:
            # 如果项目出现了别的格式，就加上else if
            resp = self.session.request(method,url,data=data,**kwargs)
        print(f"请求头为:{self.session.headers}")
        print(f"请求方式为:{method}")
        print(f"请求url为:{resp.url}")
        print(f"请求数据为请求数据为:{data}")
        print(f"请求响应码为:{resp.status_code}")
        print(f"响应数据为:{resp.json()}")
        return resp
