import os
import json
from serialize import serialize_tx
from util import double_sha256

# START
mempool_dir = './mempool'
# Get a list of all files in the mempool_dir
transactions = os.listdir(mempool_dir)
# print("Verifying ", len(transactions), "transactions...")


with open('output.txt', 'w') as output:
    # First line: The block header.
    output.write('03000000795012fe4313db18725bf4e3c96908f3f99147bca7cd4f010000000000000000a676193ad9ba98b698a83932e2588147058bfe733d89f562962636e343a5839ed95168564fe60d182ef82329')
    output.write('\n')
    # Second line: The serialized coinbase transaction.
    output.write('010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db0120000000000000000000000000000000000000000000000000000000000000000000000000')
    output.write('\n')
    # Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction
    #(need to print coinbase tx)

    counter = 0
    for filename in os.listdir(mempool_dir):
        filepath = os.path.join(mempool_dir, filename)
        with open(filepath, 'r') as file:
            tx_data = json.load(file)
            raw_tx = serialize_tx(tx_data['version'], tx_data['vin'], tx_data['vout'], tx_data['locktime'])
            tx_id = double_sha256(bytes.fromhex(raw_tx)).hex()
            output.write(tx_id)
            output.write('\n')
            counter += 1
            if(counter == 100):
                break