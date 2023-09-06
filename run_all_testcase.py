import unittest
import unittestreport
import os
# #加载用例，生成测试报告
# from common import HTMLTestRunner
from handle_tools.handle_path  import *
import unittest
import time
# def create_suite():
#     suite=unittest.TestSuite()
#     case_dir=path_project.Test_Dir
#     dis=unittest.defaultTestLoader.discover(
#         start_dir=case_dir,
#         pattern='test_*.py',
#         top_level_dir=None
#     )
#     suite.addTests(dis)
#     return suite

# #生成一个测试报告
# report_dir=local_config.Report_Dir
# now=time.strftime('%y_%m_%d_%H_%M_%S')
# report_name=report_dir+now+'_weixin_api.html'
# fp=open(report_name,'w',encoding='utf-8')

# runner=HTMLTestRunner.HTMLTestRunner(
#     stream=fp,
#     title='微信公众号接口测试报告',
#     description="微信公众号接口测试报告"
# )

cur_time=time.strftime("%Y%m%m-%H%M%S",time.localtime())
case=unittest.TestLoader().discover(os.path.join(path_project,"case"))

runner=unittestreport.TestRunner(case,filename=cur_time+"report.html",
                 report_dir="./reports",
                 title='测试报告',
                 tester='wwh',
                 desc="项目测试生成的报告",
                 templates=2)

# fp.close()
runner.run()