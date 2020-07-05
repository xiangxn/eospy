import sys
sys.path.append('../eospy')

from binascii import hexlify, unhexlify
from nose.tools import raises
from eospy.serialize import SerialBuffer
from eospy.utils import base58ToBinary, binaryToBase58, convertLegacyPublicKey

from eospy.utils import decimalToBinary, binaryToDecimal

from eospy.utils import dateToTimePoint, timePointToDate, dateToTimePointSec, timePointSecToDate
import datetime as dt
import time
import json

import eospy.cleos
from eospy.types import Abi, PackedTransaction, Transaction

class TestSerialize:
    
    def setup(self) :
        self.ce = eospy.cleos.Cleos('https://api-bostest.blockzone.net')
    
    def test_datetime(self):
        
        d1 = "2019-01-01T08:08:08"
        d2 = "2020-03-03T15:17:13"
        d3 = "2020-01-20T00:00:00"

        d = dt.datetime.strptime(d2, "%Y-%m-%dT%H:%M:%S")
        v1 = dateToTimePoint(d2)
        v2 = dateToTimePointSec(d2)
        v3 = time.mktime(d.timetuple())
        print("\nv1=", v1, "\t\tv2=", v2, "\t\tv3=", v3)
        s1 = timePointToDate(v1)
        s2 = timePointSecToDate(v2)
        print("s1=", s1, "\ts2=", s2)

    def test_serialize_abi(self) :
        eosio_abi = self.ce.get_abi('eosio')
        abi = Abi(eosio_abi["abi"])
        owner_auth = {
            "threshold": 1,
            "keys": [{
                "key": "EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo",
                "weight": 1
            }],
            "accounts": [],
            "waits": []
        }
        active_auth ={
            "threshold": 1,
            "keys": [{
                "key": "EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo",
                "weight": 1
            } ],
            "accounts": [],
            "waits": []
        }
        data = {
            "creator": "bitsfleamain",
            "newact": "n1h3qsftu5bm",
            "owner": owner_auth,
            "active": active_auth
        }
        hexs = abi.json_to_bin("newaccount", data)
        #print(hexs)
        assert "309d9146c585b33b204fd179613b5a9801000000010002271e00bde7ea56bfa78210ebb026ec9e16d6d02948880e7a39589b62ba4186340100000001000000010002271e00bde7ea56bfa78210ebb026ec9e16d6d02948880e7a39589b62ba41863401000000" == hexs
        
        bitsfleamain_abi = self.ce.get_abi('bitsfleamain')
        abi = Abi(bitsfleamain_abi['abi'])
        data = {
            "uid": 0,
            "product": {"pid":0,"uid":0,"title":"title test","description":"description 测试","photos":["photos 测试"],"category":1,"status":0,"is_new":False,"is_returns":True,"reviewer":0,"sale_method":0,"price":"100.0000 BOS","transaction_method":1,"stock_count":1,"is_retail":False,"postage":"1.0000 BOS","position":"位置","release_time":"2020-01-20T00:00:00"},
            "pa": None
        }
        hexs = abi.json_to_bin("publish", data)
        #print(hexs)
        assert "00000000000000000000000000000000000000000a7469746c652074657374126465736372697074696f6e20e6b58be8af95010d70686f746f7320e6b58be8af95010000000000000000000000000100000000000000000040420f000000000004424f5300000000010100000000102700000000000004424f530000000006e4bd8de7bdae80ed245e00" == hexs
    
    def test_uint128(self):
        data = decimalToBinary(16, "36893488153293773579")
        assert "36893488153293773579" == binaryToDecimal(data)
        data = decimalToBinary(16, "0x0b5b285e010000000200000000000000")
        assert "36893488153293773579" == binaryToDecimal(data)
        
    def test_serialize_json(self):
        json = '{"creator":"bitsfleamain","newact":"n1h3qsftu5bm","owner":{"threshold":1,"keys":[{"key":"EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo","weight":1}],"accounts":[],"waits":[]},"active":{"threshold":1,"keys":[{"key":"EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo","weight":1}],"accounts":[],"waits":[]}}'
        binstr = "309d9146c585b33b204fd179613b5a9801000000010002271e00bde7ea56bfa78210ebb026ec9e16d6d02948880e7a39589b62ba4186340100000001000000010002271e00bde7ea56bfa78210ebb026ec9e16d6d02948880e7a39589b62ba41863401000000"
        buffer = SerialBuffer()
        buffer.pushName("bitsfleamain")
        buffer.pushName("n1h3qsftu5bm")
        buffer.pushUint32(1)
        buffer.pushVarUint32(1)
        buffer.pushPublicKey("EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo")
        buffer.pushUint16(1)
        buffer.pushVarUint32(0)
        buffer.pushVarUint32(0)
        buffer.pushUint32(1)
        buffer.pushVarUint32(1)
        buffer.pushPublicKey("EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo")
        buffer.pushUint16(1)
        buffer.pushVarUint32(0)
        buffer.pushVarUint32(0)
        bufstr = buffer.getByteArray().hex()
        assert binstr == bufstr
    
    def test_serialize(self):
        buffer = SerialBuffer()
        buffer.pushUint16(16)
        buffer.pushUint32(32)
        buffer.pushUint64(1212121212121212)
        buffer.pushVarUint32(332)
        buffer.pushVarInt32(3332)
        buffer.pushFloat32(3.2)
        buffer.pushFloat64(6.4)
        buffer.pushName("bitsfleamain")
        buffer.pushBytes(b"bitsfleamain")
        buffer.pushString("Qmf58to6L2bepqMjiCiGiwpumXZYuhgwbWw2EdBQgF22JF")
        buffer.pushSymbolCode("FMP")
        buffer.pushSymbol("FMP", 4)
        buffer.pushAsset("123.4560 FMP")
        buffer.pushAsset("-123.4560 FMP")
        buffer.pushPublicKey("EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo")
        buffer.pushPublicKey("PUB_K1_5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrJJkRbz")
        buffer.pushUint128("36893488153293773579")
        buffer.pushTimePoint("2020-03-03T15:17:13")
        buffer.pushTimePointSec("2020-01-20T00:00:00")
        buffer.restartRead()
        
        assert 16 == buffer.getUint16()
        assert 32 == buffer.getUint32()
        assert 1212121212121212 == buffer.getUint64()
        assert 332 == buffer.getVarUint32()
        assert 3332 == buffer.getVarInt32()
        assert 3.2 == buffer.getFloat32()
        assert 6.4 == buffer.getFloat64()
        assert "bitsfleamain" == buffer.getName()
        assert b"bitsfleamain" == buffer.getBytes()
        assert "Qmf58to6L2bepqMjiCiGiwpumXZYuhgwbWw2EdBQgF22JF" == buffer.getString()
        assert "FMP" == buffer.getSymbolCode()
        assert ("FMP", 4) == buffer.getSymbol()
        assert "123.4560 FMP" == buffer.getAsset()
        assert "-123.4560 FMP" == buffer.getAsset()
        assert "EOS5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrHNyWbo" == buffer.getPublicKey()
        assert "PUB_K1_5BiYrPwXwFmrjLQ3ZUa3BX9crdomJNfYdu6uC863XAXrJJkRbz" == buffer.getPublicKey(False)
        assert "36893488153293773579" == buffer.getUint128()
        assert "2020-03-03T15:17:13" == buffer.getTimePoint()
        assert "2020-01-20T00:00:00" == buffer.getTimePointSec()
        
        
    def test_packed_transaction(self):
        sign = "SIG_K1_KXwkbgk7qhZV63RjbioM63hMv1L5g2DtwDetfemcHEMqDW9HmoCHfUKZgKaaq4pFm1gBwCjRP33a86fQKFQppZLKPLE2D9"
        #td = "3FD7015F9BD5E8FE57C60000000001309D9146C585B33B000000A061178FAE01804D5A55BFBF036D00000000A8ED3232E8011F00000000000000000000001F000000000000000861736466617364660B7364666173646661736466022E516D663538746F364C32626570714D6A69436947697770756D585A59756867776257773245644251674632324A462E516D56743452736E4B4654384364484138523478566E337742344636637975614B37426D7864584A3268534278570400000000000000000000000100000000000000000000102700000000000001424F5300000000010100000000640000000000000001424F53000000001DE59089E69E97E79C8120E69DBEE58E9FE5B88220E689B6E4BD99E5B882F846025F0000"
        td = "AE02F75E7830F3166C580000000001309D9146C585B33B00808A6ED15BB3C201804D5A55BFBF036D00000000A8ED32323A804D5A55BFBF036D0100012E516D663538746F364C32626570714D6A69436947697770756D585A59756867776257773245644251674632324A4600"
        trx = {"signatures":[sign],
               "compression":0,
               "packed_context_free_data":"",
               "packed_trx": td}
        trx_obj = PackedTransaction(trx['packed_trx'],self.ce).get_transaction()
        print(json.dumps(trx_obj))
        
        
        