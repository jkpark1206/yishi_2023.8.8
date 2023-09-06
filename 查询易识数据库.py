#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@Time : 2022/8/9 下午12:29
@Author : wuxi
@File : 数据库链接.py
@Project : feature-yicha-apifuzz
"""
import json
from datetime import datetime
from sqlalchemy import create_engine, desc, distinct, or_
from sqlalchemy.orm import relationship, backref
from sqlalchemy import ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, BigInteger, LargeBinary, Float
from sqlalchemy.dialects.postgresql import JSONB

# 注意：由于该模块跑在docker容器里，这里的数据库host，需要用到宿主机的ip
engine = create_engine(f'postgresql://postgres:123456@192.168.5.242:25432/ys_yishi')
Base = declarative_base()
Session = sessionmaker(bind=engine)

session = Session()

import base64


# from anafirm.common.logs import logger


class Base64Crypto:

    def crypoto(self, data):
        return base64.b64encode(str.encode(data))

    def decode(self, decode_data):
        try:
            return base64.b64decode(decode_data.decode()).decode()
        except Exception as e:
            # logger.log('ERROR', f'解码失败原因{e}')
            return ''


av_dict = {
    'N': '- 网络（N），漏洞可被远程利用，攻击者可通过网络（包括internet）远程发起攻击。',
    'A': '- 相邻网络攻击（A），攻击仅限于在逻辑相邻的网络拓扑。攻击必须从同一各共享物理网络（例如，蓝牙或 IEEE 802.11）或逻辑网络（例如，本地 IP 子网）发起，或者从安全或其他受限的管理域（如MPLS、安全 VPN 到管理网络区域）发起。',
    'L': """- 本地（L），
  - 攻击者通过本地（如键盘、控制台）或者远程（如SSH）访问目标系统。
  - 攻击者利用他人执行操作（如，诱使合法用户打开恶意文档）。""",
    'P': '- 物理（P），攻击者必须物理接触或操纵该组件。',
}

#  攻击复杂度（AC）
ac_dict = {
    'L': '- 低（L）攻击难度低，不需要特殊设备或环境，对攻击者本身能力要求低。',
    'H': """- 高（H）攻击难度高，需要具备以下条件之一才可攻击成功：
  - 必须收集攻击目标的环境信息。（如，配置信息、序列号或共享机密信息。）
  - 必须准备目标环境以提高利用漏洞的可靠性。（如，重复利用此漏洞赢得争用条件，或克服高级漏洞利用缓解技术）
  - 攻击者必须将自己诸如目标和受害者请求的资源之间的逻辑网络路径中，以便读取和/或修改网络通信（如：中间人攻击。）""",
}

#  权限要求（PR）
pr_dict = {
    'N': '- 无要求（N），攻击者不需要访问目标系统。',
    'L': '- 低权限要求（L），攻击者需要普通用户功能的权限。',
    'H': '- 高权限要求（H），攻击者需要管理控制权限。',
}

#  用户交互（UI）
ui_dict = {
    'N': '- 无交互（N），攻击者不需要其他用户的操作。',
    'R': '- 有交互（R），攻击者需要其他用户进行一些操作。如，只有在系统管理员安装应用期间才能进行攻击。',
}

#  影响范围（S）
s_dict = {
    'C': '- 会扩散（C），漏洞影响范围会扩大到其他组件，受攻击的组件和受影响的组件不是同一个，并且由不同的安全机构（如，应用程序、操作系统、固件、沙盒环境）管理。',
    'U': '- 不扩散（U），漏洞影响范围不会扩大到其他组件，或者受攻击的组件和受影响的组件在同一个安全机构（如，应用程序、操作系统、固件、沙盒环境）管理。',
}

#  机密性影响度（C）
c_dict = {
    'H': '- 高（H），完全失去机密性，导致受影响组件中的所有资源都泄露给攻击者。或者，仅获取某些受限信息，但披露的信息会产生直接、严重的影响。例如，攻击者窃取管理员的密码或 Web 服务器的私有加密密钥。',
    'L': '- 低（L），部分机密性损失。攻击者获得对某些受限制信息的访问权限，但无法控制获得的信息，或者损失的数量或种类受限。信息泄露不会对受影响的组件造成直接的严重损失。',
    'N': '- 无（N），无机密性损失。',
}

#  完整性影响度（I）
i_dict = {
    'H': '- 高（H），完全丧失了完整性，或者完全失去了保护。例如，攻击者能够修改受影响组件保护的所有文件。或者，只能修改某些文件，但恶意修改会对受影响的组件造成直接、严重的后果。',
    'L': '- 低（L），攻击者能够修改数据，但无法控制修改的后果，或者修改的数量是有限的。数据修改不会对受影响的组件产生直接、严重的影响。',
    'N': '- 无（N），受影响组件不会失去完整性。',
}

#  可用性影响度（A）
a_dict = {
    'H': '- 高（H），完全失去可用性，攻击者可以完全拒绝对受影响组件中的资源的访问。或者，攻击者能够拒绝某些可用性，但可用性的丢失会给受影响的组件带来直接而严重的后果（如，攻击者无法中断现有连接，但可以阻止新连接；攻击者可以反复利用漏洞，每次攻击造成内存泄露，重复攻击后导致服务不可用）。',
    'L': '- 低（L），性能降低或资源可用性中断。攻击者无法实现受影响组件完全拒绝向合法用户提供服务。受影响组件中的资源要么始终部分可用，要么仅在部分时间完全可用，但总体而言，受影响的组件不会产生直接的严重后果。',
    'N': '- 无（N），对受影响组件中的可用性没有影响。',
}

##cvss2的基准
#  攻击途径(AV)


av_dict_2 = {
    'N': '- 网络（N），只能通过本地访问来利用的漏洞，要求攻击者拥有对易受攻击的系统或本地（shell）帐户的物理访问。 局部例子，可利用的漏洞是外围攻击，例如 Firewire/USB DMA 攻击，以及本地权限提升（例如，sudo）。',
    'A': '- 相邻网络攻击（A），可通过相邻网络访问利用的漏洞要求攻击者能够访问易受攻击软件的广播域或冲突域。 本地网络的示例包括本地 IP 子网、蓝牙、IEEE 802.11 和本地以太网段。',
    'L': '- 本地（L），可通过网络访问利用的漏洞意味着易受攻击的软件绑定到网络堆栈，攻击者不需要本地网络访问或本地访问。 这种漏洞通常被称为“可远程利用”。 网络攻击的一个例子是 RPC 缓冲区溢出。',
}

#  攻击复杂度（AC）
ac_dict_2 = {
    'L': """- 低（L）攻击难度低，不存在专门的准入条件或情有可原的情况，以下是示例：
  - 受影响的产品通常需要访问广泛的系统和用户，可能是匿名和不受信任的（例如，面向 Internet 的 Web 或邮件服务器）。
  - 受影响的配置是默认的或普遍存在的。
  - 攻击可以手动执行，只需要很少的技能或额外的信息收集。
  - “比赛条件”是一种懒惰的条件（即，它在技术上是一场比赛，但很容易获胜）。""",
    'M': """- 中（M）攻击难度中，访问条件有些特殊，以下是示例：
  - 攻击方仅限于具有某种授权级别的一组系统或用户，可能不受信任。 在成功发起攻击之前，必须收集一些信息。
  - 受影响的配置是非默认的，并且通常不配置（例如，当服务器通过特定方案执行用户帐户身份验证时存在漏洞，但对于其他身份验证方案不存在）。
  - 该攻击需要少量社交工程，有时可能会欺骗谨慎的用户（例如，修改网络浏览器状态栏以显示虚假链接的网络钓鱼攻击，在发送 IM 漏洞之前必须在某人的“好友”列表中）。""",
    'H': """- 高（H）攻击难度高，需要具备以下条件之一才可攻击成功：
  - 例如，在大多数配置中，攻击方必须已经拥有提升的权限或欺骗攻击系统之外的其他系统（例如，DNS 劫持）。攻击依赖于社会工程方法，知识渊博的人很容易发现。
  - 例如，受害者必须执行几个可疑或非典型行为。易受攻击的配置在实践中很少见。如果存在竞争条件，则窗口非常窄。""",
}

#  身份验证（Au）
au_dict_2 = {
    'M': '- 多种（M）利用该漏洞需要攻击者进行两次或多次身份验证，即使每次都使用相同的凭据。 例如，攻击者除了提供凭据以访问托管在该系统上的应用程序外，还对操作系统进行身份验证。',
    'S': '- 单个（S）访问和利用该漏洞需要一个身份验证实例。',
    'N': '- 无（N）访问和利用漏洞不需要身份验证。',
}

#  机密性影响度（C）
c_dict_2 = {
    'C': '- 完整（C）存在全面信息泄露，导致所有系统文件被泄露。 攻击者能够读取系统的所有数据（内存、文件等）。',
    'P': '- 部分（P）有大量信息披露。 可以访问某些系统文件，但攻击者无法控制获取的内容，或者丢失的范围受到限制。 一个示例是仅泄露数据库中某些表的漏洞。',
    'N': '- 无（N）对系统的机密性没有影响。',
}

#  完整性影响度（I）
i_dict_2 = {
    'C': '- 完整（C）系统完整性完全妥协。 系统保护完全丧失，导致整个系统受到损害。 攻击者能够修改目标系统上的任何文件。',
    'P': '- 部分（P）可以修改某些系统文件或信息，但攻击者无法控制可以修改的内容，或者攻击者可以影响的范围有限。 例如，系统或应用程序文件可能被覆盖或修改，但攻击者无法控制哪些文件受到影响，或者攻击者只能在有限的上下文或范围内修改文件。',
    'N': '- 无（N）对系统的完整性没有影响。',
}

#  可用性影响度（A）
a_dict_2 = {
    'C': '- 完整（C）受影响的资源完全关闭。 攻击者可以使资源完全不可用。',
    'P': '- 部分（P）资源可用性降低或中断。 一个例子是基于网络的洪水攻击，它允许有限数量的成功连接到 Internet 服务。',
    'N': '- 无（N）对系统的可用性没有影响。',
}
aes_crypto = Base64Crypto()


class CVECNInfo(Base):
    __tablename__ = 'ys_cve_cn_info'
    id = Column(Integer, primary_key=True)  # 主键
    name = Column(LargeBinary)  # cve的中文名称
    cve_id = Column(String(30))  # cve的id
    cnnvd_id = Column(String(100), default='')  # CNNVD的编号
    cnnvd_url = Column(String(100), default='')  # CNNVD的url地址
    severity = Column(Integer, default=0)  # 危害等级: 0-未知，1-低，2-中，3-高，4-超危
    desc = Column(LargeBinary)  # cve漏洞简介
    solution = Column(LargeBinary)  # cve漏洞公告或修复建议
    related_cwe = Column(String(30), default='')  # cve关联的cwe
    cvss_3 = Column(Float)  # cvss_3评分
    cvss_2 = Column(Float)  # cvss_2评分
    cve_av_3 = Column(LargeBinary)  # 攻击途径
    cve_ac_3 = Column(LargeBinary)  # 攻击复杂度
    cve_pr = Column(LargeBinary)  # 权限要求（PR）
    cve_ui = Column(LargeBinary)  # 用户交互（UI）
    cve_s = Column(LargeBinary)  # 影响范围（S）
    cve_c_3 = Column(LargeBinary)  # 机密性影响度（C）
    cve_i_3 = Column(LargeBinary)  # 完整性影响度（I）
    cve_a_3 = Column(LargeBinary)  # 可用性影响度（A）
    cve_au = Column(LargeBinary)  # 身份验证（Au）

    cve_av_2 = Column(LargeBinary)  # 攻击途径
    cve_ac_2 = Column(LargeBinary)  # 攻击复杂度
    cve_c_2 = Column(LargeBinary)  # 机密性影响度（C）
    cve_i_2 = Column(LargeBinary)  # 完整性影响度（I）
    cve_a_2 = Column(LargeBinary)  # 可用性影响度（A）

    published = Column(String(30))  # 发布时间
    last_modified = Column(String(30))  # 更新时间

    # source = Column(String(200))  # 漏洞来源
    # vuln_type = Column(String(100))  # 漏洞类型
    # thrtype = Column(String(30))  # 威胁类型：远程、本地等等
    # company = Column(String(100))  # 厂商
    # refs = Column(Text)  # 更新参考网址
    # software_list = Column(Text)  # 受影响实体

    def cve_display(self, cve_info, cve3_dict, cve2_dict=None):
        if not cve_info:
            return None
        val = aes_crypto.decode(cve_info).strip()
        for k, v in cve3_dict.items():
            if v == val:
                return k
        if cve2_dict:
            for k, v in cve2_dict.items():
                if v == val:
                    return k
        return None

    @property
    def dict(self):
        # from anafirm.cve_cve_info import av_dict, a_dict, ac_dict, pr_dict, ui_dict, s_dict, c_dict, i_dict, \
        #     au_dict_2, av_dict_2, ac_dict_2, a_dict_2, i_dict_2, c_dict_2
        if self.published:
            a_list = self.published.split('T')[0].split('-')
            published = f'{a_list[0]}年{a_list[1]}月{a_list[2]}日'
        else:
            published = ''
        if self.cvss_3:
            self.cve_av = self.cve_av_3
            self.cve_ac = self.cve_ac_3
            self.cve_c = self.cve_c_3
            self.cve_i = self.cve_i_3
            self.cve_a = self.cve_a_3
        else:
            self.cve_av = self.cve_av_2
            self.cve_ac = self.cve_ac_2
            self.cve_c = self.cve_c_2
            self.cve_i = self.cve_i_2
            self.cve_a = self.cve_a_2
        return {
            'id': self.id,
            'name': aes_crypto.decode(self.name) if self.name else None,
            'cve_id': self.cve_id,
            'cnnvd_id': self.cnnvd_id,
            'cnnvd_url': self.cnnvd_url,
            'severity': self.severity,
            'desc': aes_crypto.decode(self.desc) if self.desc else None,
            'solution': aes_crypto.decode(self.solution) if self.solution else None,
            'cvss_3': self.cvss_3 if self.cvss_3 else None,
            'cvss_2': self.cvss_2 if self.cvss_2 else None,
            'cve_av': self.cve_display(self.cve_av, av_dict, av_dict_2),
            'cve_ac': self.cve_display(self.cve_ac, ac_dict, ac_dict_2),
            'cve_pr': self.cve_display(self.cve_pr, pr_dict),
            'cve_ui': self.cve_display(self.cve_ui, ui_dict),
            'cve_s': self.cve_display(self.cve_s, s_dict),
            'cve_c': self.cve_display(self.cve_c, c_dict, c_dict_2),
            'cve_i': self.cve_display(self.cve_i, i_dict, i_dict_2),
            'cve_a': self.cve_display(self.cve_a, a_dict, a_dict_2),
            'cve_au': self.cve_display(self.cve_au, au_dict_2),
            'related_cwe': self.related_cwe,
            'published': published,
        }

    @property
    def down_dict(self):
        # from anafirm.cve_cve_info import av_dict, a_dict, ac_dict, pr_dict, ui_dict, s_dict, c_dict, i_dict, \
        #     au_dict_2, av_dict_2, ac_dict_2, a_dict_2, i_dict_2, c_dict_2
        if self.published:
            a_list = self.published.split('T')[0].split('-')
            published = f'{a_list[0]}年{a_list[1]}月{a_list[2]}日'
        else:
            published = ''

        return {
            'id': self.id,
            'name': aes_crypto.decode(self.name) if self.name else None,
            'cve_id': self.cve_id,
            'cnnvd_id': self.cnnvd_id,
            'cnnvd_url': self.cnnvd_url,
            'severity': self.severity,
            'desc': aes_crypto.decode(self.desc) if self.desc else None,
            'solution': aes_crypto.decode(self.solution) if self.solution else None,
            'cvss_3': self.cvss_3 if self.cvss_3 else None,
            'cvss_2': self.cvss_2 if self.cvss_2 else None,
            'cve_pr': self.cve_display(self.cve_pr, pr_dict),
            'cve_ui': self.cve_display(self.cve_ui, ui_dict),
            'cve_s': self.cve_display(self.cve_s, s_dict),
            'cve_au': self.cve_display(self.cve_au, au_dict_2),
            'related_cwe': self.related_cwe,
            'published': published,

            'cve_av_3': self.cve_display(self.cve_av_3, av_dict),
            'cve_ac_3': self.cve_display(self.cve_ac_3, ac_dict),
            'cve_c_3': self.cve_display(self.cve_c_3, c_dict),
            'cve_i_3': self.cve_display(self.cve_i_3, i_dict),
            'cve_a_3': self.cve_display(self.cve_a_3, a_dict),

            'cve_av_2': self.cve_display(self.cve_av_2, av_dict, av_dict_2),
            'cve_ac_2': self.cve_display(self.cve_ac_2, ac_dict, ac_dict_2),
            'cve_c_2': self.cve_display(self.cve_c_2, c_dict, c_dict_2),
            'cve_i_2': self.cve_display(self.cve_i_2, i_dict, i_dict_2),
            'cve_a_2': self.cve_display(self.cve_a_2, a_dict, a_dict_2),
        }


class SoftWareLicense(Base):
    """开源软件对应的开源许可证表"""
    __tablename__ = 'ys_license_info'
    id = Column(Integer, primary_key=True)  # 主键
    soft_name = Column(String(100), index=True)  # 开源软件的名称
    soft_version = Column(Text)  # 开源软件的版本号列表: 默认空表示所有的版本
    license_name = Column(LargeBinary)  # 开源软件的许可证名称列表

    @property
    def dict(self):
        return {
            'id': self.id,
            'soft_name': self.soft_name,
            'soft_version': json.loads(self.soft_version),
            'license_name': json.loads(aes_crypto.decode(self.license_name)),
        }


class ScanResult(Base):
    '''FirmWare扫描结果表'''
    __tablename__ = 'ys_firmware_scan_result'
    id = Column(Integer, primary_key=True)  # 主键
    # task_id = Column(Integer, ForeignKey("ys_firmware_scan_task.id"), index=True,
    #                  comment="FirmWare扫描任务id")  # FirmWare扫描任务id

    meta = Column(Text, comment="固件任务的元数据")  # 固件任务的元数据
    plugin = Column(JSONB, comment='插件分析结果', default={})

    cwe_file = Column(Text, default=json.dumps({}), comment="")
    # 固件漏洞文件对应的漏洞信息{'file_name1': {'file_path': None, 'cwe_name': ['cwe123', 'cwe456']},}
    cwe_count = Column(Text, default=json.dumps({}), comment="cwe扫描结果数量统计")  # cwe扫描结果数量统计
    cve_count = Column(Text, default=json.dumps({}), comment="cve扫描结果数量统计")  # cve扫描结果数量统计
    is_delete = Column(Boolean,  comment="")  # cve扫描结果数量统计

    # task = relationship("FirmWareScanTask", backref="task_result")

    @property
    def dict(self):
        count_data = {'all': 0, 'unknown': 0, 'lower': 0, 'middle': 0, 'high': 0, 'super': 0}
        cve_count_data = json.loads(self.cve_count)
        cwe_count_data = json.loads(self.cwe_count)
        self_plugin = json.loads(self.plugin)
        if "cve_lookup" in self_plugin:
            if not cve_count_data:
                cve_count_data = count_data
        if "cwe_checker" in self_plugin:
            if not cwe_count_data:
                cwe_count_data = count_data

        print('INFOR', f'cwe_count_data:{cwe_count_data}')
        ans = {
            "id": self.id,
            "task_id": self.task_id,
            "meta": json.loads(self.meta) if self.meta else {},
            "cwe_file": json.loads(self.cwe_file) if self.cwe_file else {},
            # "cwe_count": json.loads(self.cwe_count) if self.cwe_count else {},
            "cwe_count": cwe_count_data,
            # "cve_count": json.loads(self.cve_count) if self.cve_count else {},
            "cve_count": cve_count_data,
            "create_time": self.create_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for plugin_name in REPORT_PLUGIN.values():
            ans.update({plugin_name: json.loads(self.plugin).get(plugin_name, {})})
        for plugin_name in [ys_cpu, ys_type]:
            ans.update({plugin_name: json.loads(self.plugin).get(plugin_name, {})})
        return ans


def cvss3_rank(score: float):
    """
    根据cvss3评分判断漏洞等级
    :param score:
    :return:
    """
    if score == 0:
        return 0  # 未知
    elif 0.1 <= score <= 3.9:
        return 1  # 低
    elif 4.0 <= score <= 6.9:
        return 2  # 中
    elif 7.0 <= score <= 8.9:
        return 3  # 高
    else:
        return 4  # 超


def cvss2_rank(score: float):
    """
    根据cvss2评分判断漏洞等级
    :param score:
    :return:
    """
    if 0 <= score <= 3.9:
        return 1  # 低
    elif 4.0 <= score <= 6.9:
        return 2  # 中
    else:
        return 3  # 高


class CWEInfo(Base):
    __tablename__ = 'ys_cwe_info'
    id = Column(Integer, primary_key=True)  # 主键
    name = Column(String(50), index=True)  # cwe的编号
    cn_name = Column(LargeBinary)  # cwe的中文名称
    desc = Column(LargeBinary)  # cwe描述
    cvss = Column(Float, nullable=True)  # 平均cvss评分
    available = Column(Integer)  # 可利用性
    result_list = Column(Text)  # 常见后果列表
    re_sug = Column(LargeBinary)  # 修复建议
    severity = Column(Integer)  # cve的严重程度


class LicenseInfo(Base):
    """开源许可证表"""
    __tablename__ = 'ys_license_detail'
    id = Column(Integer, primary_key=True)  # 主键
    lic_name = Column(LargeBinary)  # 许可证名称
    lic_type = Column(String(20))  # 类型
    lic_intro = Column(LargeBinary)  # 简介
    lic_web = Column(LargeBinary)  # 官网
    content = Column(LargeBinary)  # 内容
    lic_perm = Column(LargeBinary)  # 许可权限
    pro_perm = Column(LargeBinary)  # 禁止权限
    lic_con = Column(LargeBinary)   # 许可证条件
    update_time = Column(DateTime, default=datetime.now)  # 更新时间

    @property
    def dict(self):
        return {
            'id': self.id,
            'lic_name': aes_crypto.decode(self.lic_name),
            'lic_type': self.lic_type,
            'lic_intro': aes_crypto.decode(self.lic_intro).replace("\\r\\n", "\r\n"),
            'lic_web': aes_crypto.decode(self.lic_web),
            'content': aes_crypto.decode(self.content).replace("\\r\\n", "\r\n"),
            'lic_perm': aes_crypto.decode(self.lic_perm),
            'pro_perm': aes_crypto.decode(self.pro_perm),
            'lic_con': aes_crypto.decode(self.lic_con),
            'update_time': self.update_time.strftime("%Y-%m-%d %H:%M:%S")
        }

cwe_789 = {
    'name': 'CWE-789',
    'cn_name': '内存分配过大',
    'desc': """该产品根据不可信的大小值分配内存，但它不确保大小在预期限制内，从而允许分配任意数量的内存量。""",
    'cvss': 5.43,
    'available': 3,
    'result_list': [
        {'range': """可用性""",
         'result': """***技术影响：***

不控制内存分配可能会导致请求过多的系统内存，可能会因内存不足而导致应用程序崩溃，或者消耗系统上的大量内存。""",
         'possible': ''},
    ],
    're_sug': """- **构架与设计阶段：**

针对影响分配的内存量的任何值执行充分的输入验证。定义适当的策略来处理超出限制的请求，并考虑支持配置选项，以便管理员可以在必要时扩展要使用的内存量。

- **实施阶段：**

使用系统提供的内存资源限制运行程序。这可能仍然会导致程序崩溃或退出，但对系统其余部分的影响将被最小化""",
}

# name=cwe_task['name'],
# cn_name=aes_crypto.crypoto(cwe_task['cn_name']),
# desc=aes_crypto.crypoto(cwe_task['desc']),
# cvss=cwe_task['cvss'],
# available=cwe_task['available'],
# result_list=json.dumps(cwe_task['result_list']),
# re_sug=aes_crypto.crypoto(cwe_task['re_sug']),
# severity=cvss_rank(cwe_task['cvss'])


# page = 1
# count = 0
# while page < 40:
#     result_query_list = session.query(CVECNInfo).order_by(desc('id')).limit(5000).offset((page - 1) * 5000).all()
#     if result_query_list:
#         for result_query in result_query_list:
#             print(count)
#             count += 1
#             if result_query.cvss_3:
#                 result_query.severity = cvss3_rank(result_query.cvss_3)
#             else:
#                 if result_query.cvss_2:
#                     result_query.severity = cvss2_rank(result_query.cvss_2)
#     session.add_all(result_query_list)
#     session.commit()
#     page += 1
# print(type(result_query))
# result_query.cve_c = aes_crypto.crypoto(c_dict_2['P'])
# session.add(result_query)
# session.commit()

# result_query_list = session.query(CVECNInfo).filter(CVECNInfo.severity == 0,
#                                                     or_(CVECNInfo.cvss_3.notin_([0]),
#                                                         CVECNInfo.cvss_2.notin_([0]))).all()
# for result_query in result_query_list:
#     if result_query.cvss_3:
#         result_query.severity = cvss3_rank(result_query.cvss_3)
#     else:
#         if result_query.cvss_2:
#             result_query.severity = cvss2_rank(result_query.cvss_2)


#query后接查询表的名字     filter后面接查询表的字段
query_list = session.query(ScanResult).filter(ScanResult.is_delete==False).all()
for query in query_list:
    plugin_data = json.loads(query.plugin)
    if "cpu_architecture" in plugin_data:
        if "ARM, 64-bit, little endian (M)" in plugin_data["cpu_architecture"]["summary"]:
            print(query.id)


# result_query.cn_name = aes_crypto.crypoto(cwe_789['cn_name'])
# result_query.desc = aes_crypto.crypoto(cwe_789['desc'])
# result_query.cvss = cwe_789['cvss']
# result_query.available = cwe_789['available']
# result_query.result_list = json.dumps(cwe_789['result_list'])
# result_query.re_sug = aes_crypto.crypoto(cwe_789['re_sug'])
# result_query.severity = 2

# print(result_query.name)
# session.add(result_query)
# session.commit()
# session.add_all(result_query_list)
# session.commit()

session.close()