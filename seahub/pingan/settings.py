# -*- coding: utf-8 -*-
import seahub.settings as settings

## for oauth access token
# 测试： http://esg-oauth-stg.paic.com.cn/oauth/oauth2/access_token
# 生产： http://esg-oauth-super.paic.com.cn/oauth/oauth2/access_token
# client_id：P_ifbss-mobfile
# client_secret： 测试 cp488XdS  生产 m9R7SAD5
# grant_type：client_credentials
PINGAN_PACAS_GET_ACCESS_TOKEN_URL = getattr(settings, 'PINGAN_PACAS_GET_ACCESS_TOKEN_URL', 'http://esg-oauth-stg.paic.com.cn/oauth/oauth2/access_token')
PINGAN_PACAS_CLIENT_ID = getattr(settings, 'PINGAN_PACAS_CLIENT_ID', 'P_ifbss-mobfile')
PINGAN_PACAS_CLIENT_SECRET = getattr(settings, 'PINGAN_PACAS_CLIENT_SECRET', 'cp488XdS')
PINGAN_PACAS_GRANT_TYPE = getattr(settings, 'PINGAN_PACAS_GRANT_TYPE', 'client_credentials')

## for pacas api
# companyCode：PA011
# unitCode：IFBSS_MOBFILE

# 测试 http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/getRequestId.do
# 生产 http://esg-open.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/getRequestId.do
PINGAN_PACAS_GET_REQUEST_ID_URL = getattr(settings, 'PINGAN_PACAS_GET_REQUEST_ID_URL', 'http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/PA011/IFBSS_MOBFILE/getRequestId.do')
PINGAN_PACAS_APP_ID = getattr(settings, 'PINGAN_PACAS_APP_ID', '')
PINGAN_PACAS_V_USERNAME = getattr(settings, 'PINGAN_PACAS_V_USERNAME', '')

## auth by username and password
# 测试 http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/authenticate.do
# 生产 http://esg-open.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/authenticate.do
PINGAN_PACAS_AUTHENTICATE_URL = getattr(settings, 'PINGAN_PACAS_GET_REQUEST_ID_URL', 'http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/PA011/IFBSS_MOBFILE/authenticate.do')

## auth by cookie
# 测试 http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/authenticateBySSO2.do
# 生产 http://esg-open.paic.com.cn/open/appsvr/public/casapi/v2/{companyCode}/{unitCode}/authenticateBySSO2.do
PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL = getattr(settings, 'PINGAN_PACAS_AUTHENTICATE_BY_SSO_URL', 'http://esg-open-stg.paic.com.cn/open/appsvr/public/casapi/v2/PA011/IFBSS_MOBFILE/authenticateBySSO2.do')
