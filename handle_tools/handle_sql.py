import psycopg2.extras
from configparser import ConfigParser
from handle_tools.handle_path import path_project
import os
import pandas as pd
class Handle_sql:
    #初始化方法
    def __init__(self):
        #使用ConfigParser（）读取.ini配置文件：1、导入模块；2、读取.ini文件路径；3、使用read()读取.ini文件内容，需要加入2个参数：文件路径,编码方式
        try:
            conf = ConfigParser()
            # 定位server.ini文件路径
            sql_path = os.path.join(path_project,'conf','database.ini')
            #使用read()读取.ini文件内容
            conf.read(sql_path,encoding='utf-8')

            self.conn = psycopg2.connect(
                host='192.168.1.208',
                port=15432,
                user='postgres',
                password=123456,
                database='ys_yishi',
                # cursor_factory=psycopg2.extras.DictCursor  #以字典的样式返回数据
            )
            #创建游标：cursor是一个记录标识，用于一行一行迭代的访问查询返回的结果，相当于下标
            self.cur = self.conn.cursor()

        except Exception as e:
            print(e)

    def get_count(self,sql):   #传入的sql值为sql的查询语句，如：SELECT * FROM ys_users
        self.cur.execute(sql)
        self.count=self.cur.fetchall()
        print(len(self.count))

    def Close_database(self):
        # self.conn.commit()  #提交
        self.cur.close()  #关闭cursor
        self.conn.close()  #关闭数据库

Handle_sql()