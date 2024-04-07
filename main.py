import os
import json
import verify
from serialize import serialize_tx
from util import double_sha256, compute_weight_units, calculate_transaction_fees, verify_tx, serialize_coinbase, compute_block_header

#cannot exceed more than 4 million weight units, and the block header contributes counts for 320 weight units
MAX_BLOCK_WEIGHT = 3999680 - 100000
mempool_dir = './mempool'
# Get a list of all files in the mempool_dir
txid_to_sat_per_wu = {}
txid_to_wu = {}
txid_to_wtxid = {}

for filename in os.listdir(mempool_dir):
    filepath = os.path.join(mempool_dir, filename)
    with open(filepath, 'r') as file:
        tx_data = json.load(file)
        if verify_tx(tx_data) == True:
            raw_tx, serialized_witness, raw_wtxid = serialize_tx(tx_data['version'], tx_data['vin'], tx_data['vout'], tx_data['locktime'])
            tx_id = double_sha256(bytes.fromhex(raw_tx)).hex()

            weight_units = compute_weight_units(raw_tx, serialized_witness)
            #print(filename, "has",  weight_units, "weight units")
            sat_per_wu = calculate_transaction_fees(tx_data) / weight_units

            txid_to_sat_per_wu[tx_id] = sat_per_wu
            txid_to_wu[tx_id] = weight_units
            txid_to_wtxid[tx_id] = double_sha256(bytes.fromhex(raw_wtxid)).hex()

#sort valid transactions by satoshis / weight unit
txid_to_sat_per_wu = dict(sorted(txid_to_sat_per_wu.items(), key=lambda item: item[1], reverse=True))
#select transactions with constraint of max block weight units, the coinbase tx weight = 718
running_wu = 718
txids_in_block = []
wtxids_in_block = []

# Iterate through the map items
for key in txid_to_sat_per_wu:
    running_wu += txid_to_wu[key]
    if running_wu >= MAX_BLOCK_WEIGHT:
        break
    txids_in_block.append(key)
    wtxids_in_block.append(txid_to_wtxid[key])
    #print("add", key, "with weight", txid_to_sat_per_wu[key])
    #print("running block weight: ", running_wu)

#insert all 0 wtxid for coinbase transaction keep wtxids in natural byte order
wtxids_in_block.insert(0, '0000000000000000000000000000000000000000000000000000000000000000')
#wtxids_in_block = [''.join([wtxid[i:i+2] for i in range(0, len(wtxid), 2)][::-1]) for wtxid in wtxids_in_block]
coinbase_serialized = serialize_coinbase(wtxids_in_block)
coinbase_tx_id = double_sha256(bytes.fromhex(coinbase_serialized)).hex()
txids_in_block.insert(0, coinbase_tx_id)

print("running block weight: ", running_wu)
print("break")
#reverse all tx_ids
txids_in_block = [''.join([txid[i:i+2] for i in range(0, len(txid), 2)][::-1]) for txid in txids_in_block]
#mines the block
block_header = compute_block_header(txids_in_block)

#write everything to file output.txt for grader
with open('output.txt', 'w') as output:
    # First line: The block header.
    output.write(block_header)
    output.write('\n')
    # Second line: The serialized coinbase transaction.
    output.write(coinbase_serialized)
    output.write('\n')
    # Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction
    for i in range(0, len(txids_in_block)):
        txid = txids_in_block[i]
        # txid_rev = ''.join([txid[i:i+2] for i in range(0, len(txid), 2)][::-1])
        output.write(txid)
        if(i != len(txids_in_block) - 1):
            output.write('\n')

print("num txids included:", len(txids_in_block))
