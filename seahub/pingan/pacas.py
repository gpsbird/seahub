# -*- coding: utf-8 -*-

import time
import json
import urllib
import hashlib
import logging
import requests

from django.core.cache import cache
from django.http import HttpResponseRedirect

from seahub import auth
from seahub.base.accounts import User
from seahub.utils import render_error, normalize_cache_key

from seahub.pingan.settings import PINGAN_PACAS_GET_ACCESS_TOKEN_URL, \
        PINGAN_PACAS_CLIENT_ID, PINGAN_PACAS_CLIENT_SECRET, \
        PINGAN_PACAS_GRANT_TYPE, PINGAN_PACAS_GET_REQUEST_ID_URL, \
        PINGAN_PACAS_APP_ID, PINGAN_PACAS_V_USERNAME, \
        PINGAN_PACAS_AUTHENTICATE_URL, PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL

logger = logging.getLogger(__name__)

def get_access_token():

    cache_key = normalize_cache_key('PACAS_ACCESS_TOKEN')
    access_token = cache.get(cache_key, None)

    if not access_token:

        payload = {
            "client_id": PINGAN_PACAS_CLIENT_ID,
            "client_secret": PINGAN_PACAS_CLIENT_SECRET,
            "grant_type": PINGAN_PACAS_GRANT_TYPE
        }

        resp_json = requests.post(PINGAN_PACAS_GET_ACCESS_TOKEN_URL,
                data=json.dumps(payload)).json()

        access_token = resp_json.get('access_token', '')
        if not access_token:
            logger.error('failed to get access_token')
            logger.error(PINGAN_PACAS_GET_ACCESS_TOKEN_URL)
            logger.error(payload)
            logger.error(resp_json)
            return ''

        expires_in = resp_json.get('expires_in', 7200)
        cache.set(cache_key, access_token, expires_in)

    return access_token

def get_request_id(oauth_access_token):

    parameter_data = {'appId': PINGAN_PACAS_APP_ID}
    url = PINGAN_PACAS_GET_REQUEST_ID_URL + '?' + urllib.parse.urlencode(parameter_data)

    signature = hashlib.md5(PINGAN_PACAS_APP_ID + PINGAN_PACAS_V_USERNAME).hexdigest()
    payload = {
        "appId": PINGAN_PACAS_APP_ID,
        "vUserName": PINGAN_PACAS_V_USERNAME,
        "signature": signature,
        "access_token": oauth_access_token,
        "request_id": int(time.time()), # 只要每个请求传的值不一样就可以，建议传时间戳毫秒数
    }

    resp_json = requests.post(url, data=json.dumps(payload)).json()
    request_id= resp_json["content"].get("requestId", '')
    if not request_id:
        logger.error('failed to get request id')
        logger.error(PINGAN_PACAS_GET_REQUEST_ID_URL)
        logger.error(payload)
        logger.error(resp_json)
        return ''

    return request_id

def authenticate(username, password, oauth_access_token, request_id, source_ip):

    parameter_data = {'appId': PINGAN_PACAS_APP_ID}
    url = PINGAN_PACAS_AUTHENTICATE_URL + '?' + urllib.parse.urlencode(parameter_data)

    signature = hashlib.md5(request_id + PINGAN_PACAS_APP_ID + username +
            password + source_ip).hexdigest()

    payload = {
        "appId": PINGAN_PACAS_APP_ID,
        "requestId": request_id,
        "userId": username,
        "password": password,
        "sourceIP": source_ip,
        "signature": signature,
        "access_token": oauth_access_token,
        "request_id": int(time.time()), # 只要每个请求传的值不一样就可以，建议传时间戳毫秒数
    }

    resp_json = requests.post(url, data=json.dumps(payload)).json()
    if resp_json['code'] != 'SUCCESS':
        logger.error('failed to authenticate')
        logger.error(PINGAN_PACAS_AUTHENTICATE_URL)
        logger.error(payload)
        logger.error(resp_json)
        return False

    return True

def authenticate_by_sso(username, password, oauth_access_token, request_id,
        source_ip, sso_type, sso_cookie):

    parameter_data = {'appId': PINGAN_PACAS_APP_ID}
    url = PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL + '?' + urllib.parse.urlencode(parameter_data)

    signature = hashlib.md5(request_id + PINGAN_PACAS_APP_ID + sso_type +
            sso_cookie + source_ip).hexdigest()

    payload = {
        "appId": PINGAN_PACAS_APP_ID,
        "requestId": request_id,
	"ssoType": sso_type, # CAS_SSO_COOKIE, PASESSION 二选一，区分大小写
	"token": sso_cookie,
        "sourceIP": source_ip,
        "signature": signature,
        "access_token": oauth_access_token,
        "request_id": int(time.time()), # 只要每个请求传的值不一样就可以，建议传时间戳毫秒数
    }

    resp_json = requests.post(url, data=json.dumps(payload)).json()

    if resp_json['code'] != 'SUCCESS':
        logger.error('failed to authenticate by sso')
        logger.error(PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL)
        logger.error(payload)
        logger.error(resp_json)
        return ''

    username = resp_json["content"].get("username", '')
    if not request_id:
        logger.error('failed to get username')
        logger.error(PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL)
        logger.error(payload)
        logger.error(resp_json)
        return ''

    return username

def pacas_login(request):

    oauth_access_token = get_access_token()
    request_id = get_request_id(oauth_access_token)
    source_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')

    if request.method == "POST":

        username = request.POST.get('login', '')
        password = request.POST.get('password', '')

        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return render_error(request, '未找到用户')

        if not user.is_active:
            return render_error(request, '用户未激活')

        login_success = authenticate(username, password,
                oauth_access_token, request_id, source_ip)

        if not login_success:
            return render_error(request, '身份验证失败，请联系管理员解决')

    if request.method == "GET":

        if request.COOKIES.get('CAS_SSO_COOKIE'):
            sso_cookie = request.COOKIES.get('CAS_SSO_COOKIE')
            sso_type = 'CAS_SSO_COOKIE'
        elif request.COOKIES.get('PASESSION'):
            sso_cookie = request.COOKIES.get('PASESSION')
            sso_type = 'PASESSION'
        else:
            logger.error('fail to get CAS_SSO_COOKIE or PASESSION')
            return render_error(request, '身份验证失败，请联系管理员解决')

        username = authenticate_by_sso(username, password,
                oauth_access_token, request_id, source_ip, sso_type, sso_cookie)

        if not username:
            logger.error('fail to authenticate by sso, username: %s' % username)
            return render_error(request, '身份验证失败，请联系管理员解决')

        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return render_error(request, '未找到用户')

        if not user.is_active:
            return render_error(request, '用户未激活')

    # seahub login user
    request.user = user
    auth.login(request, user)
    redirect_to = request.GET.get(auth.REDIRECT_FIELD_NAME, '/')
    return HttpResponseRedirect(redirect_to)
