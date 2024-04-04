import os
import json
from serialize import serialize_tx

# START
mempool_dir = './mempool'
# Get a list of all files in the mempool_dir
transactions = os.listdir(mempool_dir)
# print("Verifying ", len(transactions), "transactions...")

# First line: The block header.
print('00000000000000000020cf2bdc6563fb25c424af588d5fb7223461e72715e4a9')
# Second line: The serialized coinbase transaction.
print('010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db0120000000000000000000000000000000000000000000000000000000000000000000000000')
# Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction
#(need to print coinbase tx)

counter = 0
for filename in os.listdir(mempool_dir):
    filepath = os.path.join(mempool_dir, filename)
    with open(filepath, 'r') as file:
        tx_data = json.load(file)
        print(serialize_tx(tx_data['version'], tx_data['vin'], tx_data['vout'], tx_data['locktime']))
        counter += 1
        if(counter == 100):
            break