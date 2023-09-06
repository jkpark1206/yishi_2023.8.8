import os

# 当前路径
path_handle_path = os.path.abspath(__file__)


# 项目路径
path_project = os.path.dirname(path_handle_path)

print(path_project)