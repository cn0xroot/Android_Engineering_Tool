#!/usr/bin/python3 
'''
python3 Gen_OPT_Key.py -k MySecretKey
'''

import hashlib
import time
from datetime import datetime, timedelta
import argparse

class OTPSecurity:

    def CheckOTP(self, input_str, key):
        print("Inputted input is", input_str)
        print("Inputted key is", key)
        for i in range(5, -1, -1):
            offset_str = self.GetDateString(i)
            message = (key + offset_str).encode('utf-8')
            correct_key = self.MakeHashCode(message)
            print("Offset is:", i)
            print("Correct key is:", correct_key)
            if input_str == str(correct_key):
                return True
        return False

    def GetDateString(self, min_offset):
        now = datetime.utcnow() - timedelta(minutes=min_offset)
        year_month_day_string = now.strftime("%y%m%d")
        hour_minute_string = now.strftime("%H%M")
        return year_month_day_string + hour_minute_string

    def MakeHashCode(self, message):
        hash_object = hashlib.sha256(message)
        hex_dig = hash_object.hexdigest()
        return int(hex_dig, 16) % (10 ** 6)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="the key used to generate OTP")
    args = parser.parse_args()

    if not args.key:
        print("-k or --key parameter is required.")
        exit()

    otp = OTPSecurity()
    key = args.key
    print("Unix Time output of input:", otp.MakeHashCode(key.encode('utf-8')))
    print(otp.CheckOTP("", key))
