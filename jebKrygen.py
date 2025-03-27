#!/usr/bin/env python3
#https://bbs.pediy.com/
import os, sys, struct, time, binascii, hashlib

RC4_Key2 = b'Eg\xa2\x99_\x83\xf1\x10'

def rc4(Key, inData):
    buf = bytearray()
    S = list(range(256))
    K = (list(Key) * (256 // len(Key) + 1))[:256]
    j = 0
    for i in range(256):
        j = (S[i] + K[i] + j) % 256
        S[i], S[j] = S[j], S[i]
    i, j = 0, 0
    for x in inData:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        buf.append(S[(S[j] + S[i]) % 256] ^ x) 
    return bytes(buf)

def Long2Int(longdata):
    return (longdata >> 32) & 0x7FFFFFFF, longdata & 0xFFFFFFFF

def KeygenSN(LicenseSerial, MachineID):
    mhi, mlo = Long2Int(MachineID)
    lhi, llo = Long2Int(LicenseSerial)
    hi_Key = (mhi - lhi + 0x55667788) & 0x7FFFFFFF
    lo_Key = (mlo + llo + 0x11223344) & 0xFFFFFFFF
    Z0, = struct.unpack('<Q', struct.pack('<LL', lo_Key, hi_Key))
    Z1 = int(time.time()) ^ 0x56739ACD
    s = sum(int(d, 16) for d in f"{Z1:x}") % 10
    return f"{Z0}Z{Z1}{s}"

def ParsePost(buf):
    Info = struct.unpack('<3L2Q4LQ3L', buf[:0x40])
    flag, CRC, UserSerial, LicenseSerial, MachineID, build_type, \
          Ver_Major, Ver_Minor, Ver_Buildid, Ver_Timestamp, \
          TimeOffset, Kclass, Random2 = Info
    SysInfoData = buf[0x40:]
    assert CRC == binascii.crc32(buf[8:]) & 0xFFFFFFFF
    return Info, SysInfoData

def DecodeRc4Str(buf):
    buf = bytes.fromhex(buf)
    return ParsePost(rc4(buf[:8] + RC4_Key2, buf[8:]))

def GetJebLicenseKey():
    licdata = input("Input License Data:\n")
    if licdata:
        i, MachineID = DecodeRc4Str(licdata)
        SN = KeygenSN(i[3], i[4])
        print("JEB License Key:", SN)
        return SN

GetJebLicenseKey()
input("Enter to Exit...")