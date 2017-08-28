# -*- coding: utf-8 -*-

import os
import sys
import uuid
import json
import requests
import re
from datetime import datetime
import urllib
import hashlib
import hmac
import time

DIR = os.path.dirname(os.path.realpath(__file__))
REQUEST_URL = 'https://alidns.aliyuncs.com/'
LOCAL_FILE = os.path.join(DIR, 'ip.txt')
ALIYUN_SETTINGS = os.path.join(DIR,'aliyun_settings.json')
print time.strftime('%Y-%m-%d %H:%M:%S')

with open(ALIYUN_SETTINGS, 'r') as f:
    settings = json.loads(f.read())

DEF_RR = settings['RR'] if 'RR' in settings else ['@', 'www']

def get_common_params(settings):
    """
    获取公共参数
    参考文档：https://help.aliyun.com/document_detail/29745.html?spm=5176.doc29776.6.588.sYhLJ0
    """
    return {
        'Format': 'json',
        'Version': '2015-01-09',
        'AccessKeyId': settings['access_key'],
        'SignatureMethod': 'HMAC-SHA1',
        'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'SignatureVersion': '1.0',
        'SignatureNonce': uuid.uuid4()
    }


def get_signed_params(http_method, params, settings):
    """
    参考文档：https://help.aliyun.com/document_detail/29747.html?spm=5176.doc29745.2.1.V2tmbU
    """

    # 1、合并参数，不包括Signature
    params.update(get_common_params(settings))
    # 2、按照参数的字典顺序排序
    sorted_params = sorted(params.items())
    # 3、encode 参数
    query_params = urllib.urlencode(sorted_params)
    # 4、构造需要签名的字符串
    str_to_sign = http_method + "&" + urllib.quote_plus("/") + "&" + urllib.quote_plus(query_params)
    # 5、计算签名
    signature = hmac.new(str(settings['access_secret'] + '&'), str(str_to_sign), hashlib.sha1).digest().encode('base64').strip(
        '\n')  # 此处注意，必须用str转换，因为hmac不接受unicode，大坑！！！
    # 6、将签名加入参数中
    params['Signature'] = signature

    return params


def update_yun(ip):
    """
    修改云解析
    参考文档：
        获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
        修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
    """

    # 首先获取解析列表
    get_params = get_signed_params('GET', {
        'Action': 'DescribeDomainRecords',
        'DomainName': settings['domain'],
        'TypeKeyWord': 'A'
    }, settings)

    get_resp = requests.get(REQUEST_URL, params=get_params)

    records = get_resp.json()
    print 'get_records============'
    print str(records)
    for record in records['DomainRecords']['Record']:
        if not record['RR'] in DEF_RR:
            continue
        post_params = get_signed_params('POST', {
            'Action': 'UpdateDomainRecord',
            'RecordId': record['RecordId'],
            'RR': record['RR'],
            'Type': record['Type'],
            'Value': ip
        }, settings)
        post_resp = requests.post(REQUEST_URL, post_params)
        result = post_resp.json()
        print 'updated: {0}'.format(record['RR'])
        print result


def get_curr_ip():
    headers = {
        'content-type': 'text/html',
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0'
    }
    # resp = requests.get('http://www.baidu.com/s?word=ip&_t={}'.format(int(time.time()), headers=headers))
    # soup = BS(resp.content, 'html.parser')
    # return soup.select('#1')[0]['fk']
    response = urllib.urlopen('http://api.ipify.org/?format=text')
    return response.read()


def get_lastest_local_ip():
    """
    获取最近一次保存在本地的ip
    """
    if not os.path.isfile(LOCAL_FILE):
        return 'null'
    with open(LOCAL_FILE, 'r') as f:
        last_ip = f.readline()
    return last_ip


if __name__ == '__main__':
    ip = get_curr_ip()
    if not ip:
        print u'获取ip失败，请稍后重试~'
    else:
        last_ip = get_lastest_local_ip()
        print 'ip: {0}, local: {1}'.format(ip, last_ip)

        if ip != last_ip or 'update' in sys.argv:
            if len(sys.argv) > 2:
                DEF_RR = sys.argv[2:]
                print 'use: {0}'.format(DEF_RR)

            with open(LOCAL_FILE, 'wb') as f:
                f.write(ip)
            update_yun(ip)
        else:
            print u'unchanged, no need update.'
