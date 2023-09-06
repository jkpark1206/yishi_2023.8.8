import os

# 当前路径
path_handle_path = os.path.abspath(__file__)

# tools路径  path_tools为文件名为path_handle_path的目录
path_tools = os.path.dirname(path_handle_path)

# 项目yishi_api_2的路径
path_project = os.path.dirname(path_tools)

# # app.bin路径
# path_firmware_app = os.path.join(path_project,"firmware","测试固件","app.bin")
#
# # 不可用固件路径
# path_firmware_no_have = os.path.join(path_project,"firmware","漏洞库文件","cve_cpe.db")
#
# # cwe固件路径
# path_firmware_cwe = os.path.join(path_project,"firmware","测试固件","libcurl_7.17.1-1_arm.ipk")

# print(path_project)