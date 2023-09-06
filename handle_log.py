import loguru
import sys


from loguru import logger
'''logger.info("msg msg msg!")


from loguru import logger
logger.add("file_name.log")
logger.error("msg msg msg!")


from loguru import logger
logger.debug("That's it, beautiful and simple logging!")'''


# logger.add(sys.stderr, format="{time} {level} {message}", filter="my_module", level="INFO")

from loguru import logger
#add('生成日志文件debug.log'，格式：时间+等级+
logger.add("debug.log", format="{time} {level} {message}", filter='', level="INFO")
logger.debug("This is a debug msg")
logger.info("This is a info beautiful msg")


logger.add("file_1.log", rotation="500 MB")    # 文件过大（超过500M）就会重新生成一个文件
logger.add("file_2.log", rotation="12:00")     # 每天12点创建新文件
logger.add("file_3.log", rotation="1 week")    # 文件时间过长就会创建新文件
logger.add("file_4.log", retention="10 days")  # 一段时间后会清空
logger.add("file_5.log", compression="zip")    # 保存zip格式


# logger.info("If you're using Python {}, prefer {feature} of course!", 3.6, feature="f-strings")

#
@logger.catch
def main(x, y, z):
    return x * y / z

res = main(1,2,0)
print(res)

#
# logger.add("somefile.log", enqueue=True)
#
logger.add("out.log", backtrace=True, diagnose=True)  # Caution, may leak sensitive data in prod

def func(a, b):
    return a / b

def nested(c):
    try:
        func(5, c)
    except Exception as e:
        logger.exception(e)

nested(0)


