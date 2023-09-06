import pytest
import os
import time
from common.session_init import *

import warnings
from unittestreport import ddt,list_data,yaml_data,json_data

class Test_Login():
    name = "易识v2.3"

    # 前置类
    @classmethod
    def setUpClass(cls) -> None:
        print(f"\n==========================={cls.name}接口测试开始===========================")
        # 解决错误 ResourceWarning: Enable tracemalloc to get the object allocation traceback
        warnings.simplefilter('ignore', ResourceWarning)

 # 登录
    def test_01_case(self):
        print(f"\n*****************{['title']}*****************")
        title='成功登录'
        url='user/login'
        params={
            "username":"wwh",
            "password":"fcea920f7412b5da7be0cf42b8c93759"
        }