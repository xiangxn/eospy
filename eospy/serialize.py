import struct
from eospy.utils import string_to_name, name_to_string
from eospy.utils import stringToPublicKey, publicKeyToString, stringToSignature, signatureToString
from eospy.utils import signatureDataSize, publicKeyDataSize
from eospy.utils import decimalToBinary, binaryToDecimal, dateToTimePoint, timePointToDate, dateToTimePointSec, timePointSecToDate
 
class SerialBuffer:
     
    def __init__(self, array=None):
        assert (array is None or isinstance(array, bytearray)), "Invalid parameter, must be bytearray"
        self.array = array or bytearray()
        self.readPos = 0
    
    @property
    def length(self):
        return len(self.array)
    
    def clear(self):
        self.array.clear()
        self.readPos = 0
         
    def hasReadData(self):
        return self.readPos < self.length
    
    def restartRead(self):
        self.readPos = 0
        
    def getByteArray(self):
        return self.array
    
    def setByteArray(self, array):
        self.array = array
        
    def hex(self):
        return self.array.hex()
    
    def pushArray(self, array):
        self.array.extend(array)
        
    def push(self, *vars):
        self.array.extend(list(vars))
        
    def get(self):
        if self.readPos < self.length:
            m = self.array[self.readPos]
            self.readPos += 1
            return m
        raise Exception({"message": "Read past end of buffer"})
    
    def pushUint8Array(self, array, length):
        if len(array) != length:
            raise Exception({"message": "Binary data has incorrect size"})
        self.pushArray(array)
        
    def getUint8Array(self, length):
        if self.readPos + length > self.length:
            raise Exception({"message": "Read past end of buffer"})
        array = self.array[self.readPos:self.readPos+length]
        self.readPos += length
        return array
    
    def pushBool(self, v):
        if not isinstance(v, bool):
            raise Exception({"message": "Read past end of buffer"})
        self.push(1 if v else 0)
        
    def getBool(self):
        v = self.get()
        return 0 if v == 0 else 1
    
    def pushUint8(self, v):
        if v != (v & 0xff):
            raise Exception({"message": "data is out of range"})
        self.push(v)
        
    def getUint8(self):
        return self.get()
    
    def pushInt8(self, v):
        if v != (v << 24 >> 24):
            raise Exception({"message": "data is out of range"})
        self.push(v)
        
    def getInt8(self):
        return self.get() << 24 >> 24
    
    def pushUint16(self, v): 
        data = struct.pack("<H", v)
        self.pushArray(data)
        
    def getUint16(self):
        v = struct.unpack("<H", self.getUint8Array(2))[0]
        return v
    
    def pushInt16(self, v):
        if v != (v << 16 >> 16):
            raise Exception({"message": "data is out of range"})
        data = struct.pack("<h", v)
        self.pushArray(data)
        
    def getInt16(self):
        v = struct.unpack("<h", self.getUint8Array(2))[0]
        return v
        
    def pushUint32(self, v):
        data = struct.pack("<I", v)
        self.pushArray(data)
        
    def getUint32(self):
        v = struct.unpack("<I", self.getUint8Array(4))[0]
        return v
    
    def pushInt32(self, v):
        data = struct.pack("<i", v)
        self.pushArray(data)
        
    def getInt32(self):
        v = struct.unpack("<i", self.getUint8Array(4))[0]
        return v
    
    def pushUint64(self, v):
        data = struct.pack("<Q", v)
        self.pushArray(data)
        
    def getUint64(self):
        v = struct.unpack("<Q", self.getUint8Array(8))[0]
        return v
    
    def pushInt64(self, v):
        data = struct.pack("<q", v)
        self.pushArray(data)
        
    def getInt64(self):
        v = struct.unpack("<q", self.getUint8Array(8))[0]
        return v
    
    def pushVarUint32(self, v):
        while True:
            if v >> 7:
                self.push(0x80 | (v & 0x7f))
                v = v >> 7
            else:
                self.push(v)
                break
    
    def getVarUint32(self):
        v = 0
        bit = 0
        while True:
            b = self.get()
            v |= (b & 0x7f) << bit
            bit += 7
            if (not (b & 0x80)):
                break
        return v
    
    def pushVarInt32(self, v):
        self.pushVarUint32((v << 1) ^ (v >> 31))

    def getVarInt32(self):
        v = self.getVarUint32()
        if (v & 1):
            return ((~v) >> 1) | 0x8000_0000
        else:
            return v >> 1
        
    def pushFloat32(self, v):
        data = struct.pack("<f", v)
        self.pushArray(data)
        
    def getFloat32(self):
        v = struct.unpack("<f", self.getUint8Array(4))[0]
        v = round(v, 7)
        return v
    
    def pushFloat64(self, v):
        data = struct.pack("<d", v)
        self.pushArray(data)
        
    def getFloat64(self):
        v = struct.unpack("<d", self.getUint8Array(8))[0]
        return v
    
    def pushName(self, s):
        if (not isinstance(s, str)):
            raise Exception({"message": "Expected string containing name"})
        data = struct.pack("<Q", string_to_name(s))
        self.pushArray(data)
        
    def getName(self):
        v = struct.unpack("<Q", self.getUint8Array(8))[0]
        return name_to_string(v)
    
    def pushBytes(self, v):
        self.pushVarUint32(len(v))
        self.pushArray(v)
        
    def getBytes(self):
        return self.getUint8Array(self.getVarUint32())
    
    def pushString(self, v):
        self.pushBytes(v.encode("utf-8"))
        
    def getString(self):
        data = self.getBytes()
        return data.decode("utf-8")
    
    def pushSymbolCode(self, name):
        if (not isinstance(name, str)):
            raise Exception({"message": "Expected string containing symbol_code"})
        a = []
        a += name.encode("utf-8")
        while (len(a) < 8):
            a.append(0)
        self.pushArray(a[:8])
        
    def getSymbolCode(self):
        a = self.getUint8Array(8)
        l = 0
        for d in a:
            if not d:
                break
            l += 1
        name = a[:l].decode("utf-8")
        return name
    
    def pushSymbol(self, name, precision):
        a = [precision & 0xff]
        a += name.encode("utf-8")
        while (len(a) < 8):
            a.append(0)
        self.pushArray(a[:8])
        
    def getSymbol(self):
        precision = self.get()
        a = self.getUint8Array(7)
        l = 0
        for d in a:
            if not d:
                break
            l += 1
        name = a[:l].decode("utf-8")
        return (name, precision)
    
    def pushAsset(self, asset, precision=None):
        if (not isinstance(asset, str)):
            raise Exception({"message": "Expected string containing asset"})
        a = asset.split(" ")
        if not precision:
            precision = len(a[0].split(".")[1])
        amount = int(float(a[0]) * (10 **precision))
        symbol = a[1]
        self.pushInt64(amount)
        self.pushSymbol(symbol, precision)
        
    def getAsset(self):
        amount = self.getInt64()
        (symbol, precision) = self.getSymbol()
        return "{amount:.{precision}f} {symbol}".format(amount=(amount/(10**precision)), precision=precision, symbol=symbol)
    
    def pushPublicKey(self, s):
        (key_type, data) = stringToPublicKey(s)
        self.push(key_type)
        self.pushArray(data)
        
    def getPublicKey(self, eos=True):
        key_type = self.get()
        data = self.getUint8Array(publicKeyDataSize)
        return publicKeyToString((key_type, data), eos)
    
    def pushSignature(self, s):
        (key_type, data) = stringToSignature(s)
        self.push(key_type)
        self.pushArray(data)
        
    def getSignature(self):
        type = self.get()
        data = self.getUint8Array(signatureDataSize)
        return signatureToString((type, data))
    
    def pushUint128(self, s):
        data = decimalToBinary(16, s)
        self.pushArray(data)
        
    def getUint128(self):
        data = self.getUint8Array(16)
        return binaryToDecimal(data)
    
    def pushChecksum256(self, hex_str):
        if hex_str.startswith("0x"):
            s = hex_str[2:]
        else:
            s = hex_str
        data = bytearray.fromhex(s)
        self.pushUint8Array(data, 32)
        
    def getChecksum256(self):
        data = self.getUint8Array(32)
        return data.hex()
    
    def pushTimePoint(self, s):
        data = dateToTimePoint(s)
        self.pushUint64(data)
        
    def getTimePoint(self):
        ms = self.getUint64()
        return timePointToDate(ms)
    
    def pushTimePointSec(self, s):
        data = dateToTimePointSec(s)
        self.pushUint32(data)
        
    def getTimePointSec(self):
        sec = self.getUint32()
        return timePointSecToDate(sec)
    
    def pushHex(self, hexs):
        if hexs.startswith("0x"):
            s = hexs[2:]
        else:
            s = hexs
        data = bytearray.fromhex(s)
        self.pushArray(data)