# -*- coding: utf-8 -*-

from pyfs_decrypt.data import decrypt

from pyfs_auth import AppAccessToken, final_app_access_token


class MiniApp(AppAccessToken):
    def __init__(self, appid=None, secret=None, ticket=None, token=None, storage=None):
        super(MiniApp, self).__init__(appid=appid, secret=secret, ticket=ticket, token=token, storage=storage)
        # tt.login(OBJECT), Refer: https://open.feishu.cn/document/uYjL24iN/uYzMuYzMuYzM
        # tt.getUserInfo(OBJECT), Refer: https://open.feishu.cn/document/uYjL24iN/ucjMx4yNyEjL3ITM
        # code2session, Refer: https://open.feishu.cn/document/uYjL24iN/ukjM04SOyQjL5IDN
        # 敏感数据处理, Refer: https://open.feishu.cn/document/uYjL24iN/ugjMx4COyEjL4ITM
        self.JSCODE2SESSION = self.OPEN_DOMAIN + '/open-apis/mina/v2/tokenLoginValidate'

    def sessionKey(self, unid=None):
        # https://developers.weixin.qq.com/community/develop/doc/00088a409fc308b765475fa4351000?highLine=session_key
        # sessionKey 非共用
        return 'feishu:{0}:{1}:sessionKey'.format(self.appid, unid or '')

    def store_session_key(self, session_key=None, unid=None):
        # Store sessionKey
        if session_key and unid:
            return self.storage.set(self.sessionKey(unid=unid), session_key)
        return False

    def get_session_info(self, appid=None, secret=None, ticket=None, token=None, code=None, unid=None, storage=None):
        """
        # 返回示例 ：
        {
            "code": 0,
            "msg": "success",
            "data": {
                "uid":"UID",
                "open_id": "OPENID",
                "union_id":"UNION_ID",
                "session_key": "SESSION_KEY",
                "tenant_key":"TENANT_KEY",
                "employee_id":"EMPLOYEE_ID",
                "token_type":"Bearer",
                "access_token":"USER_ACCESS_TOKEN",
                "expires_in":1565512680,
                "refresh_token":"USER_REFRESH_TOKEN"
            }
        }
        """
        # Update params
        self.update_params(appid=appid, secret=secret, ticket=ticket, token=token, storage=storage)
        # Fetch sessionInfo
        token = final_app_access_token(self, appid=self.appid, secret=self.secret, ticket=self.ticket, token=self.token, storage=self.storage)
        session_info = self.post(self.JSCODE2SESSION, data={'code': code, 'token': token}) if code else {}
        # Store sessionKey
        if session_info.get('code') == 0 and unid:
            self.storage.set(self.sessionKey(unid=unid), session_info.get('data', {}).get('session_key', ''))
        return session_info

    def get_session_key(self, appid=None, secret=None, ticket=None, token=None, code=None, unid=None, storage=None):
        # Update params
        self.update_params(appid=appid, secret=secret, ticket=ticket, token=token, storage=storage)
        # Fetch sessionKey
        # From storage
        session_key = '' if code or not unid else self.storage.get(self.sessionKey(unid=unid))
        # From request api
        if not session_key:
            session_key = self.get_session_info(appid=self.appid, secret=self.secret, ticket=self.ticket, token=self.token, code=code, storage=self.storage).get('session_key', '')
        return session_key

    def get_userinfo(self, appid=None, secret=None, ticket=None, token=None, code=None, unid=None, session_key=None, encryptedData=None, iv=None, storage=None):
        """
        {
            "openId": "ou_529a6770d21625dfdd792352d75fb79b",
            "watermark": {
                "timestamp": 1548251549,
                "appid": 6648491577574883592
            },
            "unionId": "ou_c68f35107bcd8abf9767c802c2887ecd"
        }
        """
        # Update params
        self.update_params(appid=appid, secret=secret, ticket=ticket, storage=storage)
        # If not encryptedData return session_info
        if not encryptedData:
            return self.get_session_info(appid=appid, secret=secret, ticket=ticket, token=token, code=code, unid=unid, storage=storage)
        # Update sessionKey
        if not session_key:
            session_key = self.get_session_key(appid=appid, secret=secret, ticket=ticket, token=token, code=code, unid=unid, storage=self.storage)
        return decrypt(session_key=session_key, encrypted_data=encryptedData, iv=iv)


miniapp = MiniApp()
store_session_key = miniapp.store_session_key
get_session_info = miniapp.get_session_info
get_session_key = miniapp.get_session_key
get_userinfo = miniapp.get_userinfo
