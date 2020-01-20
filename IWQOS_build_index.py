import numpy as np
import time
import sys
import datetime
import os
from scipy.sparse import csr_matrix
import re
import random
import hashlib
import hmac
import random
import pickle
import gmpy
from Crypto.Cipher import AES
import json
import string
from web3 import Web3
from pypbc import *
import gmpy2
from gmpy2 import mpz
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware
import struct
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

# w3 = Web3(HTTPProvider('http://localhost:8540'))
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8540"))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
# w3 = Web3(Web3.WebsocketProvider("ws://127.0.0.1:8650"))


g=mpz(2141434891434191460597654106285009794456474073127443963580690795002163321265105245635441519012876162226508712450114295048769820153232319693432987768769296824615642594321423205772115298200265241761445943720948512138315849294187201773718640619332629679913150151901308086084524597187791163240081868198195818488147354220506153752944012718951076418307414874651394412052849270568833194858516693284043743223341262442918629683831581139666162694560502910458729378169695954926627903314499763149304778624042360661276996520665523643147485282255746183568795735922844808611657078638768875848574571957417538833410931039120067791054495394347033677995566734192953459076978334017849678648355479176605169830149977904762004245805443987117373895433551186090322663122981978369728727863969397652199851244115246624405814648225543311628517631088342627783146899971864519981709070067428217313779897722021674599747260345113463261690421765416396528871227)
p=mpz(3268470001596555685058361448517594259852327289373621024658735136696086397532371469771539343923030165357102680953673099920140531685895962914337283929936606946054169620100988870978124749211273448893822273457310556591818639255714375162549119727203843057453108725240320611822327564102565670538516259921126103868685909602654213513456013263604608261355992328266121535954955860230896921190144484094504405550995009524584190435021785232142953886543340776477964177437292693777245368918022174701350793004000567940200059239843923046609830997768443610635397652600287237380936753914127667182396037677536643969081476599565572030244212618673244188481261912792928641006121759661066004079860474019965998840960514950091456436975501582488835454404626979061889799215263467208398224888341946121760934377719355124007835365528307011851448463147156027381826788422151698720245080057213877012399103133913857496236799905578345362183817511242131464964979)
q=mpz(93911948940456861795388745207400704369329482570245279608597521715921884786973)

sys.setrecursionlimit(10000)

# w3 = Web3(Web3.WebsocketProvider("ws://127.0.0.1:8650"))

model = AES.MODE_ECB

#读取kw-file关系
f_broker = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/broker.txt','rb')
broker=pickle.load(f_broker)
# print(broker)

#读取broker密钥
f_broker_key = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/broker_key.txt','rb')
broker_key=pickle.load(f_broker_key)
# print('broker_key',broker_key)

#print(len(broker_key))


##################################################初始化授权索引

authorization_index=[]
for i in range(len(broker_key)):
    au=[]
    authorization_index.append(au)






#初始化本地kw状态索引

broker_local_kw_state_index=[]
for i in range(len(broker_key)):
    state={}
    for kw in broker[i]:
        state[kw]=0
    broker_local_kw_state_index.append(state)

#链上任务索引
On_chain_task_index={}
####################build onchain task index
###################padding
def pad(a):
    b=hex(a)
    b=b[2:]
    return "0"*(64-len(b))+b



abi_build_index='''
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "ctoken",
				"type": "bytes32"
			},
			{
				"name": "dhash",
				"type": "bytes32"
			}
		],
		"name": "settask",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "p",
				"type": "bytes"
			}
		],
		"name": "setP",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "index",
				"type": "uint256"
			}
		],
		"name": "get_authorize",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "token",
				"type": "bytes32[]"
			},
			{
				"name": "value",
				"type": "bytes32[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "set_taskindex",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "cipher",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "tok",
				"type": "bytes32"
			}
		],
		"name": "get_taskindex",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "x",
				"type": "uint256"
			}
		],
		"name": "toBytes",
		"outputs": [
			{
				"name": "b",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "authori",
				"type": "bytes"
			}
		],
		"name": "setauthorize",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "authorization",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "fbpie",
				"type": "uint256"
			}
		],
		"name": "get_searchtoke",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "pp",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "a",
				"type": "bytes"
			},
			{
				"name": "b",
				"type": "bytes32"
			}
		],
		"name": "concat",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "searchfbpie",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "g",
				"type": "bytes"
			},
			{
				"name": "x",
				"type": "uint256"
			},
			{
				"name": "p",
				"type": "bytes"
			}
		],
		"name": "expmod",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "searchtok",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "task_index",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "get_returnC",
		"outputs": [
			{
				"name": "",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "fbpie",
				"type": "uint256"
			}
		],
		"name": "try1",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]	
'''

# from_account = w3.toChecksumAddress("0x3c62aa7913bc303ee4b9c07df87b556b6770e3fc")
#
from_account = w3.toChecksumAddress("0x27b756875b1ca4eea0b50f5f1cdfa1606a059fd5")
abi_build_index = json.loads(abi_build_index)
store_var_contract = w3.eth.contract(
   address=w3.toChecksumAddress('0x1b6e933d50B00a5DD5d5C2dFB7C9BbbE99585da9'),
   abi=abi_build_index)
phex = hex(int(p))

#
# #################################建立关键字-任务索引
# start1 = datetime.datetime.now()
#
# for i in range(len(broke_key)):
#     for kw in broker[i]:
#         a=broker_key[i][1]
#         ac = ((mpz(kw) % q) * (mpz(a) % q)) % q
#         gac = gmpy2.powmod(g, ac, p)
#         trap=hex(int(gac))
#         for block in broker[i][kw]:
#             trapdoor = trap + pad(broker_local_kw_state_index[i][kw])
#             broker_local_kw_state_index[i][kw]=broker_local_kw_state_index[i][kw]+1
#             label = (Web3.keccak(hexstr=trapdoor)).hex()
#             # print(label)
#             aes = AES.new(b'1234512345123451', model)
#             # 生成token
#             Tid=block
#             C = aes.encrypt(Tid)
#             #计算异或
#             G2 = label.encode('utf-8')
#             P = bytes(a ^ b for a, b in zip(G2, C ))
#             On_chain_task_index[label]=P
# end1 = datetime.datetime.now()
# print("build index time--local", end1-start1)
#
#
# #####################################################向blockchain传任务索引
#
# batchtoken=[]
# batchhash=[]
# times=0
# batchint=int(len(On_chain_task_index)/500)
# batchyue=len(On_chain_task_index)%500
# int_times=0
# for token in On_chain_task_index:
#     times=times+1
#     batchtoken.append(token)
#     batchhash.append(On_chain_task_index[token])
#     if times==500 and int_times<batchint:
#         int_times=int_times+1
#         times=0
#         # print(len(batchtoken))
#         tx_hash11=store_var_contract.functions.set_taskindex(batchtoken, batchhash,500).transact({
#             "from": from_account,
#             "gas": 30000000,
#             "gasPrice": 0,
#         })
#         # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
#         batchtoken=[]
#         batchhash=[]
#     if int_times==batchint and times==batchyue:
#         # print(len(batchtoken))
#         tx_hash12=store_var_contract.functions.set_taskindex(batchtoken, batchhash, batchyue).transact({
#             "from": from_account,
#             "gas": 30000000,
#             "gasPrice": 0,
#         })
#         # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash12)
#

##########一个一个上传
# for tok in On_chain_task_index:
#     tx_hash10=store_var_contract.functions.settask(tok, On_chain_task_index[tok]).transact({
#                 "from": from_account,
#                 "gas": 3000000,
#                 "gasPrice": 0,
#             })
#

# end2 = datetime.datetime.now()
# print("build index time--blockchain", end2-start1)


###########################################添加任务索引
#读取添加的kw-file关系
f_addbrokertask = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/addbrokertask.txt','rb')
add_brokertask=pickle.load(f_addbrokertask)
# print('addbrokertask',add_brokertask)

start2=datetime.datetime.now()

Add_On_chain_task_index={}

for i in range(len(broker_key)):
    # print('i',i)
    for kw in add_brokertask[i]:
        a = broker_key[i][1]
        ac = ((mpz(kw) % q) * (mpz(a) % q)) % q
        gac = gmpy2.powmod(g, ac, p)
        trap1 = hex(int(gac))
        for block in add_brokertask[i][kw]:
            trapdoor1 = trap1 + pad(broker_local_kw_state_index[i][kw])
            # trapdoor1 = trapdoor1.encode('utf-8')
            broker_local_kw_state_index[i][kw] = broker_local_kw_state_index[i][kw] + 1
            label1= (Web3.keccak(hexstr=trapdoor1)).hex()
            aes = AES.new(b'1234512345123451', model)
            # 生成token
            Tid = block
            C = aes.encrypt(Tid)
            # 计算异或
            G3 = label1.encode('utf-8')
            P1 = bytes(a ^ b for a, b in zip(G3, C))
            Add_On_chain_task_index[label1] = P1

end21=datetime.datetime.now()
print("add index time--local", end21-start2)



######一个一个添加task index
# for tok in Add_On_chain_task_index:
#     tx_hash10 = store_var_contract.functions.settask(tok, Add_On_chain_task_index[tok]).transact({
#         "from": from_account,
#         "gas": 3000000,
#         "gasPrice": 0,
#     })
#     tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash10)
#     print('file addition',tx_receipt.gasUsed)



############################向blockchain添加任务索引##################
additiongascost=0
print('len',len(Add_On_chain_task_index))
batchtoken=[]
batchhash=[]
times=0
batchint=int(len(Add_On_chain_task_index)/500)
batchyue=len(Add_On_chain_task_index)%500
int_times=0
for token in Add_On_chain_task_index:
    # print(token)
    # print(times)
    times=times+1
    batchtoken.append(token)
    batchhash.append(Add_On_chain_task_index[token])
    if times==500 and int_times<batchint:
        int_times=int_times+1
        times=0
        print(len(batchtoken))
        tx_hash11=store_var_contract.functions.set_taskindex(batchtoken, batchhash,500).transact({
            "from": from_account,
            "gas": 80000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
        additiongascost=additiongascost+tx_receipt.gasUsed
        # print('1',tx_receipt)
        batchtoken=[]
        batchhash=[]
    if int_times==batchint and times==batchyue and batchyue!=0:
        # print(len(batchtoken))
        tx_hash12=store_var_contract.functions.set_taskindex(batchtoken, batchhash, batchyue).transact({
            "from": from_account,
            "gas": 30000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash12)

        additiongascost = additiongascost + tx_receipt.gasUsed
        # print('2',tx_receipt)
print('file addition gas cost', additiongascost)
end22=datetime.datetime.now()
print("add index time--blockchain", end22-start2)



#####################################将授权索引加入到blockchain

start3=datetime.datetime.now()

########################构建授权索引
for i in range(len(broker_key)):
    for j in range(len(broker_key)):
        b = broker_key[j][2]
        d = gmpy2.invert(b, q)
        a = broker_key[i][1]
        ab = ((mpz(a) % q) * (mpz(d) % q)) % q
        gab = gmpy2.powmod(g, ab, p)
        # print('gab',gab)
        gabhex=hex(int(gab))
        gabhex=gabhex[2:]
        gabtian="0x"+"0"*(768-len(gabhex))+gabhex
        authorization_index[j].append(gabtian)


authoriztion={}
for i in range(len(broker_key)):
    authoriztion[broker_key[i][0]]=authorization_index[i]

end3=datetime.datetime.now()

print("authorization--local", end3-start3)


sumautho=0
######################################没个broker的授权索引，上传到blockchain上的
for aut in authoriztion:
    # print('aut',aut)
    for j in range(len(authoriztion[aut])):
        # print('authoriztion[aut][j]',authoriztion[aut][j])
        tx_hash11 = store_var_contract.functions.setauthorize(aut, authoriztion[aut][j]).transact({
            "from": from_account,
            "gas": 30000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
        sumautho=sumautho+tx_receipt.gasUsed
        print('authorization-one', tx_receipt.gasUsed)
        # print('authorization-accumulate', tx_receipt.cumulativeGasUsed)

end4=datetime.datetime.now()
print('total authorization gas cost',sumautho)
print("authorization--blockchain", end4-start3)


###############################set p###########################
phex = hex(int(p))


tx = store_var_contract.functions.setP(phex).transact({
                "from": from_account,
                "gas": 3000000,
                "gasPrice": 0,
            })
tx_receipt = w3.eth.waitForTransactionReceipt(tx)

############################定义搜索函数



def search(kw,FB12,FBpie):
    Tbw = ((mpz(kw) % q) * (mpz(FB12) % q)) % q
    return Tbw, FBpie

# def localsearch()



# startsearch=datetime.datetime.now()
# print(broker)
Tbw1, fbpie1= search(308787214124473614167655, broker_key[0][2], broker_key[0][0])
token1 = int(Tbw1)

# Tbw2, fbpie2= search(6133736384721188680745832161050472860970599, broker_key[0][2], broker_key[0][0])
# token2 = int(Tbw2)
# #
# #
# Tbw3, fbpie3= search(1469637038130182918335437370188645, broker_key[0][2], broker_key[0][0])
# token3 = int(Tbw3)
#
#
# Tbw4, fbpie4= search(322918641029749419569785, broker_key[0][2], broker_key[0][0])
# token4 = int(Tbw4)
#
#
#
# Tbw5, fbpie5= search(27047760750386508672659514216, broker_key[0][2], broker_key[0][0])
# token5 = int(Tbw5)
# #
#

###kw1
startsearch=datetime.datetime.now()

tx_hashkw1 = store_var_contract.functions.get_searchtoke(token1, fbpie1).transact({
                        "from": from_account,
                        "gas": 80000000,
                        "gasPrice": 0,
                    })
x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw1)
print('search gas cost',x_receipt.gasUsed)

# tx_hashkw2 = store_var_contract.functions.get_searchtoke(token2, fbpie2).transact({
#                         "from": from_account,
#                         "gas": 80000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw2)
#
# tx_hashkw3 = store_var_contract.functions.get_searchtoke(token3, fbpie3).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw3)
#
# ##kw4
# tx_hashkw4 = store_var_contract.functions.get_searchtoke(token4, fbpie4).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw4)
#
# ##kw5
# tx_hashkw5 = store_var_contract.functions.get_searchtoke(token5, fbpie5).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw5)



# endsearch=datetime.datetime.now()
# print("search--blockchain", endsearch-startsearch)
#
# end0 = store_var_contract.functions.get_returnC().call()
# print('onchain-number',len(end0))

# print("search -- before reveive", endsearch-end11)


#



def localsearch(Tbw,fbpie):
    cipherset=[]
    for aut in authoriztion[fbpie]:
        print(aut)
        exp=gmpy2.powmod(mpz(aut),mpz(Tbw),p)
        trap = hex(int(exp))
        c=0
        trapdoor = trap + pad(c)
        label = (Web3.keccak(hexstr=trapdoor)).hex()
        while label in Add_On_chain_task_index:
            G2 = label.encode('utf-8')
            cipher = bytes(a ^ b for a, b in zip(G2, Add_On_chain_task_index[label] ))
            cipherset.append(cipher)
            c = c + 1
            trapdoor=trap + pad(c)
            label=(Web3.keccak(hexstr=trapdoor)).hex()

    return cipherset


# startlocalsearch=datetime.datetime.now()
# a=localsearch(Tbw1, fbpie1)
# # b=localsearch(Tbw2, fbpie2)
# endlocalsearch=datetime.datetime.now()
# print('localsearch',endlocalsearch-startlocalsearch)

# print(len(a))

# tx_hashkw2 = store_var_contract.functions.get_searchtoke(token2, fbpie2).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw2)
# #


# print("search--blockchain", endsearch-startsearch)
#
# ##kw3
# tx_hashkw3 = store_var_contract.functions.get_searchtoke(token3, fbpie3).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw3)
#
# ##kw4
# tx_hashkw4 = store_var_contract.functions.get_searchtoke(token4, fbpie4).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw4)
#
# ##kw5
# tx_hashkw5 = store_var_contract.functions.get_searchtoke(token5, fbpie5).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hashkw5)
#











# end0 = store_var_contract.functions.get_returnC().call()
# print(len(end0))
# Tbw1, fbpie1 = search(308787214124473614167655, broker_key[1][2], broker_key[1][0])
# token2 = int(Tbw1)
# tx_hash12 = store_var_contract.functions.get_searchtoke(token2, fbpie1).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
#
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hash12)
# Tbw3, fbpie3 = search(308787214124473614167655, broker_key[0][2], broker_key[0][0])
# token3 = int(Tbw)
# tx_hash13 = store_var_contract.functions.get_searchtoke(token3, fbpie3).transact({
#                         "from": from_account,
#                         "gas": 40000000,
#                         "gasPrice": 0,
#                     })
#
# x_receipt = w3.eth.waitForTransactionReceipt(tx_hash13)
# bw, fbpie = search(308787214124473614167655, broker_key[1][2], broker_key[1][0])
# token1 = int(Tbw)
# tx_hash11 = store_var_contract.functions.get_searchtoke(token1, fbpie).transact({
#                         "from": from_account,
#                         "gas": 30000000,
#                         "gasPrice": 0,
#                     })










#
#
# for i in range(6):
#     for kw in broker[i]:
#         Tbw, fbpie = search(kw, broker_key[i][2], broker_key[i][0])
#         token1 = int(Tbw)
#         tx_hash11 = store_var_contract.functions.get_searchtoke(token1, fbpie).transact({
#                         "from": from_account,
#                         "gas": 30000000,
#                         "gasPrice": 0,
#                     })
#         # x_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
#         # end0 = store_var_contract.functions.get_returnC().call()
#         # end0 = store_var_contract.functions.get_returnC().call()
#         # print(len(end0))







# ######################################search
# Tbw,fbpie=search(308787214124473614167655, broker_key[0][2], broker_key[0][0])
#
# token1=int(Tbw)
# tx_hash11 = store_var_contract.functions.try1(token1, fbpie).transact({
#                 "from": from_account,
#                 "gas": 30000000,
#                 "gasPrice": 0,
#             })
# tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
# end0 = store_var_contract.functions.get_returnC().call()
#
#
# print(end0)
# print(len(end0))
#
