# -*- coding: utf-8 -*-

import os
import uuid
import json
import requests
import re
from datetime import datetime
import urllib
import hashlib
import hmac

from bs4 import BeautifulSoup as BS


REQUEST_URL = 'https://alidns.aliyuncs.com/'
LOCAL_FILE = 'ip.txt'
ALIYUN_SETTINGS = 'aliyun_settings.json'


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

	#1、合并参数，不包括Signature
	params.update(get_common_params(settings))
	#2、按照参数的字典顺序排序
	sorted_params = sorted(params.items())
	#3、encode 参数
	query_params = urllib.urlencode(sorted_params)
	#4、构造需要签名的字符串
	str_to_sign = http_method + "&" + urllib.quote_plus("/") + "&" + urllib.quote_plus(query_params)
	#5、计算签名
	signature = hmac.new(str(settings['access_secret'] + '&'), str(str_to_sign), hashlib.sha1).digest().encode('base64').strip('\n') #此处注意，必须用str转换，因为hmac不接受unicode，大坑！！！
	#6、将签名加入参数中
	params['Signature'] = signature

	return params

def update_yun(ip):
	"""
	修改云解析
	参考文档：
		获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
		修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
	"""
	with open(ALIYUN_SETTINGS, 'r') as f:
		settings = json.loads(f.read())

	#首先获取解析列表
	get_params = get_signed_params('GET', {
		'Action': 'DescribeDomainRecords',
		'DomainName': settings['domain'],
		'TypeKeyWord': 'A'
	}, settings)

	get_resp = requests.get(REQUEST_URL, get_params)

	records = get_resp.json()
	print 'get_records============'
	print records
	for record in records['DomainRecords']['Record']:
		post_params = get_signed_params('POST', {
			'Action': 'UpdateDomainRecord',
			'RecordId': record['RecordId'],
			'RR': record['RR'],
			'Type': record['Type'],
			'Value': ip
		}, settings)
		post_resp = requests.post(REQUEST_URL, post_params)
		result = post_resp.json()
		print 'update_record============'
		print result

def get_curr_ip():
	headers = {'content-type': 'text/html',
           'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0'}
	resp = requests.get('http://ip.chinaz.com/', headers=headers)
	soup = BS(resp.content, 'html.parser')
	ip_tag = soup.find_all('p', class_='getlist')[0]

	ip = None
	for string in ip_tag.strings:
		if re.match(r'(\d{1,3}\.?){4}', string):
			ip = string.strip()
			break
	return ip

def get_lastest_local_ip():
	"""
	获取最近一次保存在本地的ip
	"""
	with open(LOCAL_FILE, 'w+') as f:
		last_ip = f.readline()
	return last_ip

if __name__ == '__main__':
	ip = get_curr_ip()
	if not ip:
		print u'获取ip失败，请稍后重试~'
	else:
		last_ip = get_lastest_local_ip()
		print ip, last_ip
		if ip != last_ip:
			print u'先写到本地...'
			with open(LOCAL_FILE, 'wb') as f:
				f.write(ip)
			print u'修改云解析...'
			update_yun(ip)
