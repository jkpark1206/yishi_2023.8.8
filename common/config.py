import os

#url地址
URL='192.168.1.208:8011'

#测试用例路径
est_Dir='C:/Tools/yishi_api_2/testcase/'

# 测试报告路径
Report_Dir='C:/Tools/yishi_api_2/reports/'

#当前文件所处的路径
os_path = os.path.abspath(__file__)


# tools路径  path_tools是文件名为os_path的目录：C:/Tools/yishi_api_2/common/config.py
path_tools = os.path.dirname(os_path)


# 项目路径(yishi_api_2的路径)
path_project = os.path.dirname(path_tools)

