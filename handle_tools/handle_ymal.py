import yaml
from loguru import logger

#创建一个读取yaml文件的类

class Hadnle_Yaml:
        def __init__(self,yaml_path):
            self.yaml_path = yaml_path
            '''
            通过init把文件传入到这个类
            :param yaml_file:
            '''
        def read_yaml(self):
            '''
            读取yaml，将yaml反序列化，就是把我们yaml格式转换成dict格式
            :return:
            '''
            with open(self.yaml_path,encoding="utf-8") as f:
                value = yaml.load(f,Loader=yaml.FullLoader) #文件流，加载方式
                print(value)

if __name__ == '__main__':
    Hadnle_Yaml(r"C:\\tools\\yishi_api_2\\req_data\\case.ymal").read_yaml()

