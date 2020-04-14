from .schema import (ActionSchema, PermissionLevelSchema, ChainInfoSchema, BlockInfoSchema, 
                    TransactionSchema,
                    AbiRicardianClauseSchema, AbiTableSchema, AbiSchema, AbiTypeSchema, 
                    AbiActionSchema, AbiStructFieldSchema, AbiStructSchema, AbiErrorMessagesSchema,
                    AbiExtensionsSchema, AbiVariantsSchema, AuthoritySchema, PermissionLevelWeightSchema,
                    KeyWeightSchema, WaitWeightSchema)
import datetime as dt
import pytz
from .utils import sha256, string_to_name, name_to_string, int_to_hex, hex_to_int, char_subtraction
from .exceptions import EOSBufferInvalidType, EOSInvalidSchema, EOSUnknownObj, EOSAbiProcessingError
import json
import binascii
import struct
import six
from colander import Invalid
from collections import OrderedDict
from .serialize import SerialBuffer


# json encoder
class EOSEncoder(json.JSONEncoder) :
    def default(self, o) :
        if isinstance(o, Action) :
            return o.__dict__
        if isinstance(o, PermissionLevel) :
            return o.__dict__
        if isinstance(o, dt.datetime) :
            return o.isoformat()

class Name(str) :
    hex_str_len = 16
class AccountName(Name) : pass
class PermissionName(Name) : pass
class ActionName(Name) : pass
class TableName(Name) : pass
class ScopeName(Name) : pass

class Checksum256:
    def __init__(self, s):
        self.value = s
        
    def __str__(self):
        return self.value
    
class Uint128(int):pass

class PublicKey:
    def __init__(self, s):
        self.value = s
    
    def __str__(self):
        return self.value

class Byte(int): pass
class UInt16(int): pass
class UInt32(int): pass
class UInt64(int): pass

class Int16(int): pass
class Int32(int): pass
class Int64(int): pass

class Float(float): pass

class TimePointSec:
    def __init__(self, s):
        self.value = s
        
    def __str__(self):
        return self.value
    
class TimePoint:
    def __init__(self, s):
        self.value = s
        
    def __str__(self):
        return self.value

if six.PY3 :
    class long(int) : pass

class VarUInt :
    def __init__(self, val=""):
        ''' '''
        self._val = val
        self.buffer = SerialBuffer()

    def encode(self) :
        ''' '''
        # ensure value is an int
        val = int(self._val)
        self.buffer.clear()
        self.buffer.pushVarUint32(val)
        return self.buffer.hex()
    
    def encode(self, buf):
        val = int(self._val)
        buf.pushVarUint32(val)

    def decode(self, buf):
        return buf.getVarUint32()
    
class EOSBuffer(SerialBuffer) :
    def __init__(self, value=None) :
        super(EOSBuffer, self).__init__()
        self._value = value
            
    def decode(self, objType, buf=None):
        if not buf:
            buf = self._buffer
        if isinstance(objType, UInt32):
            val = buf.getUint32()
        elif isinstance(objType, UInt16):
            val = buf.getUint16()
        elif isinstance(objType, VarUInt):
            val = objType.decode(buf)
        elif(isinstance(objType, Byte) or
             isinstance(objType, bool)) :
            val = buf.get()
        elif isinstance(objType, Float):
            val = buf.getFloat64()
        elif(isinstance(objType, int) or
             isinstance(objType, long)) :
            val = buf.getInt32()
        elif(isinstance(objType, Checksum256)):
            val = buf.getChecksum256()
        elif(isinstance(objType, Uint128)):
            val = buf.getUint128()
        elif(isinstance(objType, PublicKey)):
            val = buf.getPublicKey()
        elif (isinstance(objType, Name) or
             isinstance(objType, AccountName) or
             isinstance(objType, PermissionName) or
             isinstance(objType, ActionName) or
             isinstance(objType, TableName) or
             isinstance(objType, ScopeName) ) :
            val = buf.getName()
        elif isinstance(objType, str):
            val = buf.getString()
        elif(isinstance(objType, list)) :
            # get count(VarUint)
            val = []
            length = buf.getVarUint32()
            while len(val) < length:
                out = self.decode(objType[0], buf)
                val.append(out)
        else:
            raise EOSBufferInvalidType("Cannot decode type: {}".format(type(objType)))
        return val

    def encode(self, val=None, buf=None) :
        if val is None :
            val = self._value
        if not buf:
            buf = self._buffer
        if (isinstance(val, Name) or
           isinstance(val, AccountName) or
           isinstance(val, PermissionName) or
           isinstance(val, ActionName) or
           isinstance(val, TableName) or
           isinstance(val, ScopeName) ) :
            buf.pushName(val)
        elif(isinstance(val, str)) :
            buf.pushString(val)
        elif(isinstance(val, Byte)):
            buf.push(val)
        elif(isinstance(val, bool)) :
            buf.pushBool(val)
        elif(isinstance(val, UInt16)) :
            buf.pushUint16(val)
        elif(isinstance(val,UInt32)) :
            buf.pushUint32(val)
        elif(isinstance(val,UInt64)) :
            buf.pushUint64(val)
        elif(isinstance(val, Uint128)):
            buf.pushUint128(val)
        elif(isinstance(val, Checksum256)):
            buf.pushChecksum256(str(val))
        elif(isinstance(val, PublicKey)):
            buf.pushPublicKey(str(val))
        elif(isinstance(val, TimePointSec)):
            buf.pushTimePointSec(str(val))
        elif(isinstance(val, TimePoint)):
            buf.pushTimePoint(str(val))
        elif(isinstance(val, Float)):
            buf.pushFloat32(val)
        elif(isinstance(val, VarUInt)) :
            val.encode(buf)
        elif(isinstance(val, int) or
             isinstance(val, long)) :
            buf.pushInt32(val)
        elif(isinstance(val, Action) or 
             isinstance(val, AbiStruct) or 
             isinstance(val, AbiStructField) or 
             isinstance(val, AbiType) or
             isinstance(val, AbiAction) or 
             isinstance(val, AbiTable) or
             isinstance(val, AbiRicardianClauses) or 
             isinstance(val, AbiErrorMessages) or
             isinstance(val, AbiExtensions) or 
             isinstance(val, AbiVariants) or
             isinstance(val, Asset) or
             isinstance(val, Authority) or
             isinstance(val, PermissionLevelWeight) or
             isinstance(val, WaitWeight) or
             isinstance(val, KeyWeight) or
             isinstance(val, PermissionLevel)):
            val.encode(buf)
        elif(isinstance(val, list)) :
            buf.pushVarUint32(len(val))
            for item in val :
                self.encode(item, buf)
        else :
            raise EOSBufferInvalidType('Cannot encode type: {}'.format(type(val)))
        
class BaseObject(object) :
    def __init__(self, d=None) :
        ''' '''
        try:
            if d:
                self._obj = self._validator.deserialize(d)
        except Invalid:
            raise EOSInvalidSchema('Unable to process schema for {}'.format(type(self)))
        # instantiate the class
        if hasattr(self, "_obj"):
            for k,v in self._obj.items() :
                setattr(self, k, v)
            # clean up
            del self._obj
            del self._validator
        
    def __repr__(self) :
        ''' '''
        return '{}({})'.format(self.__class__, self.__dict__)
        
    def _encode_buffer(self, value, buf) :
        ''' '''
        buf.encode(value, buf)

    def _create_obj_array(self, arr, class_type) :
        ''' '''
        new_arr = []
        for item in arr :
            new_arr.append(class_type(item))
        return new_arr

class Action(BaseObject) :
    def __init__(self, d) :
        ''' '''
        self._validator = ActionSchema()
        super(Action, self).__init__(d)
        # setup permissions
        self.authorization = self._create_obj_array(self.authorization, PermissionLevel)
        
    def encode(self, buf) :
        ''' '''
        buf.pushName(self.account)
        buf.pushName(self.name)
        self._encode_buffer(self.authorization, buf)
        buf.pushVarUint32(int(len(self.data)/2))
        buf.pushHex(self.data)

class Asset :
    def __init__(self, value, precision=4) :
        # self.amount = amt
        # self.symbol = sym
        # self.precision = precision
        self.from_string(value)

    def __str__(self) :
        return '{amount:.{precision}f} {symbol}'.format(amount=self.amount, symbol=self.symbol, precision=self.precision)
        
    def __add__(self, other) :
        if self.symbol != other.symbol :
            raise TypeError('Symbols must match: {} != {}', self.symbol, other.symbol)
        return Asset(self.amount+other.amount, self.symbol)

    def __sub__(self, other) :
        if self.amount - other.amount < 0 :
            raise ValueError('Subtraction would result in a negative.')
        if self.symbol != other.symbol :
            raise TypeError('Symbols must match: {} != {}', self.symbol, other.symbol)
        return Asset(self.amount-other.amount, self.symbol)

    def from_string(self, s) :
        splt = s.split()
        try :
            self.amount = float(splt[0])
            self.symbol = splt[1]
            self.precision = len(splt[0].split(".")[1])
        except IndexError:
            raise IndexError('Invalid string format given. Must be in the formst <float> <currency_type>')

    def encode(self, buf):
        ''' '''
        if buf:
            buf.pushAsset("{} {}".format(self.amount, self.symbol), self.precision)

class AbiType(BaseObject):
    def __init__(self, d):
        self._validator = AbiTypeSchema()
        super(AbiTypes, self).__init__(d)
    
    def encode(self, buf):
        self._encode_buffer(self.new_type_name, buf)
        self._encode_buffer(self.type, buf)

class AbiStructField(BaseObject):
    def __init__(self, d):
        self._validator = AbiStructFieldSchema()
        super(AbiStructField, self).__init__(d)
    
    def encode(self, buf):
        self._encode_buffer(self.name, buf)
        self._encode_buffer(self.type, buf)

class AbiStruct(BaseObject):
    def __init__(self, d):
        self._validator = AbiStructSchema()
        super(AbiStruct, self).__init__(d)
        self.fields = self._create_obj_array(self.fields, AbiStructField)
    
    def encode(self, buf):
        self._encode_buffer(self.name, buf)
        self._encode_buffer(self.base, buf)
        self._encode_buffer(self.fields, buf)

class AbiAction(BaseObject):
    def __init__(self, d):
        self._validator = AbiActionSchema()
        super(AbiAction, self).__init__(d)
    
    def encode(self, buf):
        self._encode_buffer(Name(self.name), buf)
        self._encode_buffer(self.type, buf)
        self._encode_buffer(self.ricardian_contract, buf)

class AbiTable(BaseObject):
    def __init__(self, d):
        self._validator = AbiTableSchema()
        super(AbiTable, self).__init__(d)
    
    def encode(self, buf):
        self._encode_buffer(Name(self.name), buf)
        self._encode_buffer(self.index_type, buf)
        self._encode_buffer(self.key_names, buf)
        self._encode_buffer(self.key_types, buf)
        self._encode_buffer(self.type, buf)

class AbiRicardianClauses(BaseObject):
    def __init__(self, d):
        self._validator = AbiRicardianClauseSchema()
        super(AbiRicardianClauses, self).__init__(d)
    
    def encode(self, buf):
        self._encode_buffer(self.id, buf)
        self._encode_buffer(self.body, buf)

class AbiErrorMessages(BaseObject):
    # TODO implement encode
    def __init__(self, d):
        self._validator = AbiErrorMessagesSchema()
        super(AbiErrorMessages, self).__init__(d)
    
    def encode():
        raise NotImplementedError

class AbiExtensions(BaseObject):
    # TODO implement encode
    def __init__(self, d):
        self._validator = AbiExtensionsSchema()
        super(AbiExtensions, self).__init__(d)
    
    def encode():
        raise NotImplementedError

class AbiVariants(BaseObject):
    # TODO implement encode
    def __init__(self, d):
        self._validator = AbiVariantsSchema()
        super(AbiVariants, self).__init__(d)
    
    def encode():
        raise NotImplementedError
    
class KeyWeight(BaseObject):
    def __init__(self, d=None):
        self._validator = KeyWeightSchema()
        super(KeyWeight, self).__init__(d)
        
    def encode(self, buf):
        self._encode_buffer(PublicKey(self.key), buf)
        self._encode_buffer(UInt16(self.weight), buf)
        
class WaitWeight(BaseObject):
    def __init__(self, d=None):
        self._validator = WaitWeightSchema()
        super(WaitWeight, self).__init__(d)
        
    def encode(self, buf=None):
        self._encode_buffer(UInt32(self.wait_sec), buf)
        self._encode_buffer(UInt16(self.weight), buf)
        
class PermissionLevel(BaseObject):
    def __init__(self, d=None) :
        ''' '''
        # create validator
        self._validator = PermissionLevelSchema()
        super(PermissionLevel, self).__init__(d)

    def encode(self, buf) :
        ''' '''
        self._encode_buffer(AccountName(self.actor), buf)
        self._encode_buffer(PermissionName(self.permission), buf)
        
class PermissionLevelWeight(BaseObject):
    def __init__(self, d=None):
        self._validator = PermissionLevelWeightSchema()
        super(PermissionLevelWeight, self).__init__(d)
        
    def encode(self, buf=None):
        self._encode_buffer(PermissionLevel(self.permission), buf)
        self._encode_buffer(UInt16(self.weight), buf)
        
class Authority(BaseObject):
    def __init__(self, d=None):
        self._validator = AuthoritySchema()
        super(Authority, self).__init__(d)
        if d:
            self.keys = self._create_obj_array(self.keys, KeyWeight)
            self.accounts = self._create_obj_array(self.accounts, PermissionLevelWeight)
            self.waits = self._create_obj_array(self.waits, WaitWeight)
        
    def encode(self, buf):
        self._encode_buffer(UInt32(self.threshold), buf)
        self._encode_buffer(self.keys, buf)
        self._encode_buffer(self.accounts, buf)
        self._encode_buffer(self.waits, buf)

class Abi(BaseObject):
    _abi_map = {
        # name
        'name': Name(),
        'string': str(),
        # numbers
        'bool': Byte(),
        'uint8': Byte(),
        'uint16': UInt16(),
        'uint32': UInt32(),
        'uint64': UInt64(),
        'uint128': Uint128(),
        'int8': Byte(),       
        'int16': Int16(),    
        'int32': Int32(),    
        'int64': Int64(),    
        'float64': Float(),  
        # 'varuint32': VarUInt # NotImplemented
        # complex
        'asset' : Asset("1.0000 EOS"),
        'checksum256': Checksum256(""),  
        # 'block_timestamp_type': UInt64, # NotImplemented
        'time_point': TimePoint(""),
        'time_point_sec': TimePointSec(""),
        # 'connector': str, # NotImplemented
        'public_key': PublicKey(""), 
        'authority': Authority(),  
        # 'block_header': str, # NotImplemented
        # 'bytes': str, # NotImplemented
        'permission_level': PermissionLevel(), 
        'permission_level_weight': PermissionLevelWeight(), 
        'key_weight': KeyWeight(),
        'wait_weight': WaitWeight()
    }

    def __init__(self,d):
        ''' '''
        self._validator = AbiSchema()
        super(Abi, self).__init__(d)
        self.types = self._create_obj_array(self.types, AbiType)
        self.structs = self._create_obj_array(self.structs, AbiStruct)
        self.actions = self._create_obj_array(self.actions, AbiAction)
        self.tables = self._create_obj_array(self.tables, AbiTable)
        self.ricardian_clauses = self._create_obj_array(self.ricardian_clauses, AbiRicardianClauses)
        self.error_messages = self._create_obj_array(self.error_messages, AbiErrorMessages)
        self.abi_extensions = self._create_obj_array(self.abi_extensions, AbiExtensions)
        self.variants = self._create_obj_array(self.variants, AbiVariants)

    def get_action(self, name):
        ''' '''
        for act in self.actions:
            if act.name == name:
                return act
        raise EOSUnknownObj('{} is not a valid action for this contract'.format(name))

    def get_actions(self):
        actions = []
        for act in self.actions:
            actions.append(act.name)
        return actions

    def get_struct(self, name):
        ''' '''
        for struct in self.structs:
            if struct.name == name:
                return struct
        #raise EOSUnknownObj('{} is not a valid struct for this contract'.format(name))
        return None

    def get_action_parameters(self, name):
        ''' '''
        parameters = OrderedDict()
        # get the struct
        struct = self.get_struct(name)
        for field in struct.fields:
            f = field.type.strip('[]')
            f = f.strip("?")
            ft = self.get_struct(f)
            if(f in self._abi_map):
                field_type = self._abi_map[f]
                # check if the field is a list
                if '[]' in field.type :
                    field_type = [field_type]
                parameters[field.name] = field_type
            elif ft:
                parameters[field.name] = self.get_action_parameters(f)
            else :
                raise EOSUnknownObj("{} is not a known abi type".format(field.type))
        return parameters

    def get_raw(self, buf):
        self._encode_buffer(self.version, buf)
        self._encode_buffer(self.types, buf)
        self._encode_buffer(self.structs, buf)
        self._encode_buffer(self.actions, buf)
        self._encode_buffer(self.tables, buf)
        self._encode_buffer(self.ricardian_clauses, buf)
        self._encode_buffer(self.error_messages, buf)
        self._encode_buffer(self.abi_extensions, buf)
        self._encode_buffer(self.variants, buf)

    def encode(self):
        ''' '''
        buf = EOSBuffer()
        self.get_raw(buf.getBuffer())
        raw_abi = buf.getHex()
        buf.clear()
        # divide by two because it is hex
        self._encode_buffer(VarUInt(len(raw_abi)/2), buf)
        return "{}{}".format(buf.getHex(), raw_abi)
    
    def _loop_type(self, params, data, buf):
        if data is None:
            self._encode_buffer(VarUInt("0"), buf)
            return
        for field in data:
            # create EOSBuffer with value as a type of field
            if isinstance(params[field], list):
                field_type = type(params[field][0])
                arr = []
                for f in data[field]: 
                    #print(f)
                    arr.append(field_type(f))
                self._encode_buffer(arr, buf)
            elif isinstance(params[field], OrderedDict):
                self._loop_type(params[field], data[field], buf)
            else:
                field_type = type(params[field])
                self._encode_buffer(field_type(data[field]), buf)
    
    def json_to_bin(self, name, data):
        # act = self.get_action(name)
        params = self.get_action_parameters(name)
        buf = EOSBuffer()
        self._loop_type(params, data, buf)
        return buf.hex()



class ChainInfo(BaseObject) :
    def __init__(self, d) :
        ''' '''
        self._validator = ChainInfoSchema()
        super(ChainInfo, self).__init__(d)

class BlockInfo(BaseObject) :
    def __init__(self, d) :
        ''' '''
        self._validator = BlockInfoSchema()
        super(BlockInfo, self).__init__(d)

class Transaction(BaseObject) :
    def __init__(self, d, chain_info, lib_info) :
        ''' '''
        # add defaults
        if 'expiration' not in d :
            d['expiration'] = str((dt.datetime.utcnow() + dt.timedelta(seconds=30)).replace(tzinfo=pytz.UTC))
        if 'ref_block_num' not in d :
            d['ref_block_num'] = chain_info['last_irreversible_block_num'] & 0xFFFF
        if 'ref_block_prefix' not in d :
            d['ref_block_prefix'] = lib_info['ref_block_prefix']
        # validate
        self._validator = TransactionSchema()
        super(Transaction, self).__init__(d)
        # parse actions
        self.actions = self._create_obj_array(self.actions, Action)
    
    def encode(self) :
        ''' '''
        buf = EOSBuffer()
        exp_ts = (self.expiration - dt.datetime(1970, 1, 1, tzinfo=self.expiration.tzinfo)).total_seconds()
        self._encode_buffer(UInt32(exp_ts), buf)
        self._encode_buffer(UInt16(self.ref_block_num & 0xffff), buf)
        self._encode_buffer(UInt32(self.ref_block_prefix), buf)
        self._encode_buffer(VarUInt(self.net_usage_words), buf)
        self._encode_buffer(Byte(self.max_cpu_usage_ms), buf)
        self._encode_buffer(VarUInt(self.delay_sec), buf)
        
        
        self._encode_buffer(self.context_free_actions, buf)
        self._encode_buffer(self.actions, buf)
        self._encode_buffer(self.transaction_extensions, buf)
        return buf.getArray()
        
    def get_id(self) :
        return sha256(self.encode())

class PackedTransaction:
    def __init__(self, trx, ce):
        self._cleos = ce
        self._packed_trx = trx
        # empty header
        self._is_unpacked = False
        self._unpacked_trx = OrderedDict()
        
    def _decode_header(self, buf):
        ''' '''
        # get expiration buffer
        exp = buf.decode(UInt32())
        # get expiration in UTC
        exp_dt = dt.datetime.utcfromtimestamp(exp)
        self._unpacked_trx['expiration'] = exp_dt.strftime("%Y-%m-%dT%H:%M:%S")
        # get ref_block
        ref_blk = buf.decode(UInt16())
        self._unpacked_trx['ref_block_num'] = ref_blk
        # get ref_block_prefix
        ref_blk_pre = buf.decode(UInt32())
        self._unpacked_trx['ref_block_prefix'] = ref_blk_pre
        # get net usage 
        max_net_usage = buf.decode(VarUInt())
        self._unpacked_trx['max_net_usage_words'] = max_net_usage
        # get cpu usage
        max_cpu_usage = buf.decode(Byte())
        self._unpacked_trx['max_cpu_usage_ms'] = max_cpu_usage
        # get delay sec
        delay_sec = buf.decode(VarUInt())
        self._unpacked_trx['delay_sec'] = delay_sec

    def decode_actions(self, buf):
        ''' '''
        # get length of action array
        actions = []
        length = buf.decode(VarUInt())
        cnt = 0
        # loop through array
        while cnt < length and length:
            # process action account/name
            acct_name = buf.decode(AccountName())
            action_name = buf.decode(ActionName())
            # get authorizations
            auth = self.decode_authorizations(buf)
            # get data length
            hex_data_len = buf.decode(VarUInt())
            # get abi information
            contract_abi = self._cleos.get_abi(acct_name)
            abi = Abi(contract_abi["abi"])
            abi_act = abi.get_action(action_name)
            # temp check need to handle this better
            if abi_act["type"] != action_name:
                raise EOSAbiProcessingError("Error processing the {} action".format(action_name)) 
            abi_struct = abi.get_action_parameters(action_name)
            data = OrderedDict()
            # save data for hex_data
            data_diff = act_buf
            for a in abi_struct:
                act_data = buf.decode(abi_struct[a])
                data[a] = act_data
            act = OrderedDict({
                'account': acct_name,
                'name': action_name,
                "authorization": auth,
                "data": data,
                "hex_data": data_diff.rstrip(act_buf),
            })
            actions.append(act)
            # increment count
            cnt += 1

        return actions

    def decode_authorizations(self, buf):
        ''' '''
        auths = []
        length = buf.decode(VarUInt())
        cnt = 0
        while cnt < length and length:
            # process action account/name
            acct_name = buf.decode(AccountName())
            perm = buf.decode(ActionName())
            auth = OrderedDict({
                'actor': acct_name,
                'permission': perm,
            })
            auths.append(auth)
            cnt += 1
        return auths

    # placeholder until context_free_actions are implemented. Might be able to use self.decode_actions
    def decode_context_actions(self, buf):
        ''' '''
        length = buf.decode(VarUInt(), buf)
        if length > 0:
            raise NotImplementedError("Currently eospy does not support context_free_actions")
        # get length of action array
        context_actions = []
        return context_actions

    # placeholder until context_free_actions are implemented. Might be able to use self.decode_actions
    def decode_trx_extensions(self, buf):
        ''' '''
        trx_ext = []
        length = buf.decode(VarUInt())
        if length > 0:
            raise NotImplementedError("Currently eospy does not support transaction extensions")
        # get length of action array
        return trx_ext

    def get_id(self):
        ''' '''
        return sha256(bytearray.fromhex(self._packed_trx))

    def get_transaction(self):
        ''' '''
        # only unpack once
        if not self._is_unpacked:    
            # decode the header and get the rest of the trx back
            trx_buf = EOSBuffer(SerialBuffer(bytearray.fromhex(self._packed_trx)))
            self._decode_header(trx_buf)
            # process list of context free actions
            context_actions = self.decode_context_actions(trx_buf)
            self._unpacked_trx['context_free_actions'] = context_actions
            # process actions
            actions = self.decode_actions(trx_buf)
            self._unpacked_trx['actions'] = actions
            # process transaction extensions
            trx_ext = self.decode_trx_extensions(trx_buf)
            self._unpacked_trx['transaction_extensions'] = trx_ext 
            # set boolean
            self._is_unpacked = True
        return self._unpacked_trx

