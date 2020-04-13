from binascii import hexlify, unhexlify
import struct
import hashlib
import datetime as dt
import time
import pytz
import six
from .exceptions import InvalidKeyFile

def parse_key_file(filename, first_key=True):
    keys=[]
    with open(filename) as fo: 
        lines = fo.readlines()
        for line in lines:
            if line.startswith('Private'):
                try:
                    header,key = line.replace(' ', '').rstrip().split(':')
                    if key and first_key:
                        return key
                    elif key: 
                        keys.append(key)
                except ValueError:
                    # invalid format
                    pass
    if keys:
        return keys
    raise InvalidKeyFile('Key file was in an invalid format. Must contain one key pair and have a prefix of "Private key:"')

def sha256(data):
    ''' '''
    return hashlib.sha256(data).hexdigest()

def ripemd160(data):
    ''' '''
    #h = hashlib.new('ripemd160')
    h = hashlib.new('rmd160')
    h.update(data)
    return h.hexdigest()

def ripemd160Data(data):
    h = hashlib.new('rmd160')
    h.update(data)
    return h.digest()

def sig_digest(payload, chain_id=None, context_free_data=None) :
    ''' '''
    if chain_id :
        buf = bytearray.fromhex(chain_id)
    else :
        buf = bytearray(32)
    # already a bytearray
    buf.extend(payload)
    if context_free_data :
        #buf += sha256(context_free_data)
        pass
    else :
        # empty buffer
        buf.extend(bytearray(32))
    return sha256(buf)
    
def int_to_hex(i) :
    return '{:02x}'.format(i)

def hex_to_int(i) :
    return int(i, 16)
    
def str_to_hex(c) :
    hex_data = hexlify(bytearray(c, 'ascii')).decode()
    return int(hex_data,16)

def char_subtraction(a, b, add) :
    x = str_to_hex(a)
    y = str_to_hex(b)
    ans = str((x - y) + add)
    if len(ans) % 2 == 1 :
        ans = '0' + ans
    return int(ans)

#static constexpr uint64_t char_to_symbol( char c ) {
#    if( c >= 'a' && c <= 'z' )
#       return (c - 'a') + 6;
#    if( c >= '1' && c <= '5' )
#        return (c - '1') + 1;
#    return 0;
#}
def char_to_symbol(c) :
    ''' '''
    if c >= 'a' and c <= 'z' :
        return char_subtraction(c, 'a', 6)
    if c >= '1' and c <= '5' :
        return char_subtraction(c, '1', 1)
    return 0
    
#// Each char of the string is encoded into 5-bit chunk and left-shifted
#// to its 5-bit slot starting with the highest slot for the first char.
#// The 13th char, if str is long enough, is encoded into 4-bit chunk
#// and placed in the lowest 4 bits. 64 = 12 * 5 + 4
#static constexpr uint64_t string_to_name( const char* str )
#{
#    uint64_t name = 0;
#    int i = 0;
#    for ( ; str[i] && i < 12; ++i) {
#            // NOTE: char_to_symbol() returns char type, and without this explicit
#            // expansion to uint64 type, the compilation fails at the point of usage
#            // of string_to_name(), where the usage requires constant (compile time) expression.
#            name |= (char_to_symbol(str[i]) & 0x1f) << (64 - 5 * (i + 1));
#    }
#    
#    // The for-loop encoded up to 60 high bits into uint64 'name' variable,
#    // if (strlen(str) > 12) then encode str[12] into the low (remaining)
#    // 4 bits of 'name'
#    if (i == 12)
#    name |= char_to_symbol(str[12]) & 0x0F;
#    return name;
#    }
def string_to_name(s) :
    ''' '''
    i = 0
    name = 0
    while i < len(s) :
        #sym = char_to_symbol(s[i])
        name += (char_to_symbol(s[i]) & 0x1F) << (64-5 * (i + 1))
        i += 1
    if i > 12 :
        name |= char_to_symbol(s[11]) & 0x0F
    return name


def name_to_string(n) :
    ''' '''
    charmap = '.12345abcdefghijklmnopqrstuvwxyz'
    name = ['.'] * 13
    i = 0
    while i <= 12:
        c = charmap[n & (0x0F if i == 0 else 0x1F)]
        name[12-i] = c
        n >>= 4 if i == 0 else 5
        i += 1
    return ''.join(name).rstrip('.')

# if six.PY3 :
#     def _byte(b) :
#         return bytes((b,))
# else :
#     def _byte(b) :
#         return chr(b)

# # temp
# def varint_encode(number):
#     ''' '''
#     buffer = b''
#     while True:
#         towrite = number & 0x7f
#         number >>= 7
#         if number:
#             buffer += _byte(towrite | 0x80)
#         else:
#             buffer += _byte(towrite)
#             break
#     return buffer


base58Chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
publicKeyDataSize = 33
signatureDataSize = 65

def base58ToBinary(s):
    base58_text = bytes(s, "utf8")
    n = 0
    leading_zeroes_count = 0
    for b in base58_text:
        n = n * 58 + base58Chars.find(b)
        if n == 0:
            leading_zeroes_count += 1
    res = bytearray()
    while n >= 256:
        div, mod = divmod(n, 256)
        res.insert(0, mod)
        n = div
    else:
        res.insert(0, n)
    return (bytearray(1) * leading_zeroes_count + res)

def binaryToBase58(data):
    if isinstance(data, bytearray):
        byteseq = data
    else:
        byteseq = unhexlify(bytes(data, "utf8"))
    n = 0
    leading_zeroes_count = 0
    for c in byteseq:
        n = n * 256 + c
        if n == 0:
            leading_zeroes_count += 1
    res = bytearray()
    while n >= 58:
        div, mod = divmod(n, 58)
        res.insert(0, base58Chars[mod])
        n = div
    else:
        res.insert(0, base58Chars[n])
    return (base58Chars[0:1] * leading_zeroes_count + res).decode("ascii")

def digestSuffixRipemd160(data, suffix):
    d = bytearray(data)
    for c in suffix:
        d.append(ord(c))
    h = hashlib.new('rmd160')
    h.update(d)
    return h.digest()

def stringToKey(s, type, size, suffix):
    whole = base58ToBinary(s)
    digest = digestSuffixRipemd160(whole[:publicKeyDataSize], suffix)
    if (digest[0] != whole[size + 0] or digest[1] != whole[size + 1]
        or digest[2] != whole[size + 2] or digest[3] != whole[size + 3]):
        raise Exception({"message": "checksum doesn't match"})
    return (type, whole[:publicKeyDataSize])

def keyToString(key, suffix, prefix, eos=True):
    if eos:
        digest = ripemd160Data(key[1])
    else:
        digest = digestSuffixRipemd160(key[1], suffix)
    whole = bytearray(key[1])
    for i in range(0, 4):
        whole.append(digest[i])
    return prefix + binaryToBase58(whole)

def stringToPublicKey(s):
    if not isinstance(s, str):
        raise Exception({"message": "expected string containing public key"})
    if (s[:3] == "EOS"):
        whole = base58ToBinary(s[3:])
        data = whole[:publicKeyDataSize]
        digest = ripemd160Data(data)
        if (digest[0] != whole[publicKeyDataSize] or digest[1] != whole[34] or digest[2] != whole[35] or digest[3] != whole[36]):
            raise Exception({"message": "checksum doesn't match"})
        return (0, data)
    elif (s[:7] == "PUB_K1_"):
        return stringToKey(s[7:], 0, publicKeyDataSize, "K1")
    elif (s[:7] == "PUB_R1_"):
        return stringToKey(s[7:], 1, publicKeyDataSize, "R1")
    else:
        raise Exception({"message": "unrecognized public key format"})
    
def publicKeyToString(key, eos=True):
    if (key[0] == 0 and len(key[1]) == publicKeyDataSize):
        if eos:
            return keyToString(key, "K1", "EOS", eos)
        return keyToString(key, "K1", "PUB_K1_", eos)
    elif (key[0] == 1 and len(key[1]) == publicKeyDataSize):
        return keyToString(key, "R1", "PUB_R1_", False)
    else:
        raise Exception({"message": "unrecognized public key format"})
    
def convertLegacyPublicKey(s):
    if (s[:3] == "EOS"):
        return publicKeyToString(stringToPublicKey(s), False)
    return s

def stringToSignature(s):
    if not isinstance(s, str):
        raise Exception({"message": "expected string containing signature"})
    if (s[:7] == "SIG_K1_"):
        return stringToKey(s[7:], 0, signatureDataSize, "K1")
    elif (s[:7] == "SIG_R1_"):
        return stringToKey(s[7:], 1, signatureDataSize, "R1")
    else:
        raise Exception({"message": "unrecognized signature format"})
    
def signatureToString(signature):
    if signature[0] == 0:
        return keyToString(signature, "K1", "SIG_K1_")
    elif signature[0] == 1:
        return keyToString(signature, "R1", "SIG_R1_")
    else:
        raise Exception({"message": "unrecognized signature format"})
    
def decimalToBinary(size, s):
    if s.startswith("0x") and len(s) >= size * 2 + 2:
        return bytearray.fromhex(s[2:(size * 2 + 2)])
    result = bytearray(1) * size
    for i in range(0, len(s)):
        srcDigit = ord(s[i])
        if srcDigit < 48 or srcDigit > 57:
            raise Exception({"message": "invalid number"})
        carry = srcDigit - 48
        for j in range(0, size):
            x = result[j] * 10 + carry
            mod = divmod(x, 256)[1]
            result[j] = mod
            carry = x >> 8
        if carry:
            raise Exception({"message": "number is out of range"})
    return result

def binaryToDecimal(bignum, minDigits = 1):
    result = bytearray([48]*minDigits)
    for i in range(len(bignum)-1, -1, -1):
        carry = bignum[i]
        for j in range(0, len(result)):
            x = ((result[j] - 48) << 8) + carry
            result[j] = 48 + x % 10
            carry = int(x / 10)
        while carry:
            result.append(48 + carry % 10)
            carry = int(carry / 10)
    result.reverse()
    return result.decode("ascii")

def dateParse(date):
    #if not date.endswith("Z"):
    #    date += "Z"
    d = dt.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=pytz.utc)
    return d.timestamp()

def dateToTimePoint(date):
    val = dateParse(date)
    return int(val * 1000)

def timePointToDate(ms):
    val = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms/1000))
    return val

def dateToTimePointSec(date):
    val = dateParse(date)
    return int(val)

def timePointSecToDate(sec):
    val = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec))
    return val
    