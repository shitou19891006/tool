#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Author: TheCjw<thecjw@qq.com>
# Created on 22:26 2015/2/11

__author__ = "TheCjw"

import collections
import hashlib
import json

# pip install requests
# pip install pycrypto
import requests
from Crypto.Cipher import AES


class WifiDemo(object):
    def __init__(self):
        self.salt = "LQ9$ne@gH*Jq%KOL"
        self.request_url = "http://wifiapi02.51y5.net/wifiapi/fa.cmd"

        self.request_params = {}
        self.request_params["och"] = "wandoujia"
        self.request_params["ii"] = ""
        self.request_params["appid"] = "0001"
        # self.request_params["pid"] = "qryapwithoutpwd:commonswitch"
        self.request_params["pid"] = "qryapwd:commonswitch"
        self.request_params["lang"] = "cn"
        self.request_params["v"] = "633"
        self.request_params["uhid"] = "a0000000000000000000000000000001"
        # self.request_params["method"] = "getSecurityCheckSwitch"
        self.request_params["method"] = "getDeepSecChkSwitch"
        self.request_params["st"] = "m"
        self.request_params["chanid"] = "guanwang"

        # Fill these shit.
        self.request_params["sign"] = ""
        self.request_params["bssid"] = ""
        self.request_params["ssid"] = ""

        # device id.
        # change dhid if return limited
        self.request_params["dhid"] = "4028b2ad4f8418bb01510ff505bd3b70"
        # dhid=ff80808144ab9c770144b1619d962a2f
        # dhid=ff80808144ab97920144b161ac5d2d33
        # dhid=ff8080814cc5798a014ccbbdfa375369
        # dhid=4028b29d4b72236a014b780339777ef7
        # dhid=4028b2ad4f8418bb01510ff505bd3b70
        # "4028b29d4b72236a014b780339777ef2"

        # device mac.
        self.request_params["mac"] = "d8:86:e6:6f:a8:09"

        self.headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Host": "wifiapi02.51y5.net",
            "Accept": "text/plain"
        }

    def __sign__(self, data):
        return hashlib.md5(data.encode("utf-8")).hexdigest().upper()


    def __post__(self):
        r = requests.post(self.request_url, data=self.request_params, headers=self.headers)
        return r.text

    def __add_bssid__(self, bssid):
        self.request_params["bssid"] += bssid + ","

    def __add_ssid__(self, ssid):
        self.request_params["ssid"] += ssid + ","

    def __sign_data__(self):
        self.request_params["sign"] = ""
        value = ""
        for key in collections.OrderedDict(sorted(self.request_params.items())):
            value += self.request_params[key]
        value += self.salt
        return self.__sign__(value)

    def add_ssid(self, bssid, ssid):
        self.__add_bssid__(bssid)
        self.__add_ssid__(ssid)

    def request(self):
        self.request_params["sign"] = self.__sign_data__()
        ret_data = json.loads(self.__post__())
        if ret_data["retCd"] == "-1111":
            # update key and retry.
            self.salt = ret_data["retSn"]
            return self.request()
        elif ret_data["retCd"] == "0":
            self.salt = ret_data["retSn"]
            return ret_data


def main():
    wifi = WifiDemo()

    # Add BSSID & SSID
    wifi.add_ssid("d8:b1:90:b3:52:90", "TTfund")
    #wifi.add_ssid("B8:55:10:8D:07:44", "YANG JUN JUN")

    result = wifi.request()

    if not result["qryapwd"].get("psws"):
        print result["qryapwd"]["retMsg"]
        return

    for info in result["qryapwd"]["psws"]:
        ssid = result["qryapwd"]["psws"][info]["ssid"]
        bssid = result["qryapwd"]["psws"][info]["bssid"]
        encrypt_data = result["qryapwd"]["psws"][info]["pwd"]

        cipher = AES.new(b"jh16@`~78vLsvpos", AES.MODE_CBC, b"j#bd0@vp0sj!3jnv")
        decrypt_data = cipher.decrypt(encrypt_data.decode("hex"))
        length = int(decrypt_data[:3])
        password = decrypt_data[3:][:length]

        print "ssid", ssid
        print "bssid", bssid
        print "password", password
        print


if __name__ == "__main__":
    main()