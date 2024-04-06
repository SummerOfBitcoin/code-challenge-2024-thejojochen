import hashlib
import struct
import verify
from ecdsa import SECP256k1, VerifyingKey, BadSignatureError
import serialize
import time

def double_sha256(data):
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2

def double_sha256_nodigest(data):
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1)
    return hash2

def hash160(data):
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

def int_to_compact_size(num):
    if(0 <= num <= 252):
        return num.to_bytes(1, byteorder='little').hex()
    
    elif(253 <= num <= 65535):
        return "fd" + num.to_bytes(2, byteorder='little').hex()
    
    elif(65536 <= num <= 4294967295):
        return "fe" + num.to_bytes(4, byteorder='little').hex()
    else: raise ValueError("num is too large:", num)

#TODO: implement some error checking for decoding der encoded signatures
def der_to_rawsig(der_sig):

    der_sig = der_sig[6:]
    der_sig = der_sig[2:]
    if(der_sig[:2] == "00"):
        der_sig = der_sig[2:]
    r = der_sig[:64]
    
    der_sig = der_sig[64 + 4:]
    der_sig = der_sig[:-2]
    return r, der_sig

def are_all_elements_same(arr):
    # Check if the array is empty
    if not arr:
        return True  # Empty array, so all elements are technically the same (None)

    # Compare each element with the first element
    first_element = arr[0]
    for element in arr[1:]:
        if element != first_element:
            return False  # Found an element that is different from the first element

    return True  # All elements are the same

def determine_script_type(script):
    split = script.split()
    if split[-1] == 'OP_CHECKMULTISIG':
        return 'multisig'
    
    elif split[0] == 'OP_0' and split[1] == 'OP_PUSHBYTES_20':
        return 'p2wpkh'
    
    elif split[0] == 'OP_0' and split[1] == 'OP_PUSHBYTES_32':
        return 'p2wsh'
    else:
        print('some other script type:', script)

def validate_multisig(inner_script, curr_input, curr_witness, tx_data, witness, input_index = -1):
    inner_script = inner_script.split()
    inner_script.pop()
    assert inner_script[-1][:11] == 'OP_PUSHNUM_'
    n_public_keys = int(inner_script[-1][-1])
    inner_script.pop()
    public_keys = []
    for _ in range(0, n_public_keys):
        public_keys.append(inner_script.pop())
        assert inner_script[-1] == 'OP_PUSHBYTES_33' or inner_script[-1] == 'OP_PUSHBYTES_65'
        inner_script.pop()
    
    #the keys are in order in which they appear in inner_witnessscript_asm
    public_keys = public_keys[::-1]
    assert inner_script[-1][:11] == 'OP_PUSHNUM_'
    m_signatures = int(inner_script[-1][-1])
    #save the witness_script for signature verification
    witness_script = curr_witness.pop()
    #signatures in order which they appear in witness, the first element is empty (just pop it off)
    signatures = curr_witness[1:]
    assert m_signatures == len(signatures)
    #print("we have a ", len(signatures), "of", len(public_keys), "multisig")
    #print('signatures:', signatures)
    #print('public keys:', public_keys)

    #verify multisig
    tally = 0
    for sig in signatures:
        sig_hash = struct.pack('<I', int.from_bytes(bytes.fromhex(sig[-2:]), byteorder='big')).hex()

        message = ""
        if (witness == True):
            message = serialize.serialize_segwit_msg(tx_data, sig_hash, curr_input, witness_script, is_p2wsh = True)
        elif(witness == False):
            for input_tx in tx_data["vin"]:
                input_tx["scriptsig"] = ""
            inputs = tx_data['vin']
            inputs[input_index]['scriptsig'] = witness_script
            message = serialize.serialize_tx(tx_data['version'], tx_data['vin'], tx_data['vout'], tx_data['locktime'])
            message += sig_hash
        
        
        r, s = der_to_rawsig(sig)
        raw_signature = r + s
        signature_bytes = bytes.fromhex(raw_signature)
        
        public_key_index = 0
        for i in range(0, len(public_keys)):
            pubkey = public_keys[i]
            public_key_bytes = bytes.fromhex(pubkey)
            # use public key (r concat s) to generate verifying key
            verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
            #perform verify signature
            try:
                verifying_key.verify(signature_bytes, bytes.fromhex(message), hashfunc=double_sha256_nodigest)
                tally += 1
                public_key_index = i
                break
                #print("success verifying ", sig, "against", pubkey)
            except:
                #print("failed verifying ", sig, "against", pubkey)
                public_key_index = i
        
        #ignore the public_leys that have already failed
        public_keys = public_keys[public_key_index + 1:]

    if (tally == m_signatures):
        return
    else:
        raise BadSignatureError("not enough signatures")

#test these eventually:
def serialize_witness(witness):
    num_items = int_to_compact_size(len(witness))
    serialized_witness = num_items

    for item in witness:
        serialized_witness += int_to_compact_size(int(len(item) / 2))
        serialized_witness += item
    
    return serialized_witness

def compute_weight_units(serialized_tx, serialized_witness = ''):
    non_witness_weight = (len(serialized_tx) / 2) * 4

    if serialized_witness == '':
        witness_weight = 0
    else:
        witness_weight = len(serialized_witness) / 2 * 1
    return non_witness_weight + witness_weight # +2 for marker and flag possibly

def calculate_transaction_fees(transaction):
    total_input = sum(vin['prevout']['value'] for vin in transaction['vin'])
    total_output = sum([vout['value'] for vout in transaction['vout']])
    fees = total_input - total_output
    return fees

def verify_tx(tx_data):

    for i in range(0, len(tx_data['vin'])):
        scriptpubkey_type = tx_data['vin'][i]['prevout']['scriptpubkey_type']
        try:
            if scriptpubkey_type == 'p2pkh':
                verify.verify_p2pkh(tx_data, i)
            elif scriptpubkey_type == 'p2sh':
                verify.verify_p2sh(tx_data, i)
            elif scriptpubkey_type == 'v0_p2wsh':
                verify.verify_p2wsh(tx_data, i)
            elif scriptpubkey_type == 'v0_p2wpkh':
                verify.verify_p2wpkh(tx_data, i)
            elif scriptpubkey_type == 'v1_p2tr': #TODO: try to verify p2tr
                return True
        except:
            return False
    return True

def compute_merkle_root(items, natural):
    if len(items) == 0:
        return None
    
    # reverse items if input is not in natural order
    if natural == False:
        items =  [''.join([item[i:i+2] for i in range(0, len(item), 2)][::-1]) for item in items]

    hashes = [bytes.fromhex(item) for item in items]
    while len(hashes) > 1:
        # If the number of hashes is odd, duplicate the last hash
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        pairs = [hashes[i] + hashes[i + 1] for i in range(0, len(hashes), 2)]
        hashes = [double_sha256(pair) for pair in pairs]
    
    return hashes[0].hex()

def serialize_coinbase(wtxids_in_block):

    #compute the wtxid commitment
    witness_reserved_value = '0000000000000000000000000000000000000000000000000000000000000000'
    witness_root_hash = compute_merkle_root(wtxids_in_block, True)
    wtxid_commitment = double_sha256(bytes.fromhex(witness_root_hash + witness_reserved_value)).hex()

    return '010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed' + wtxid_commitment + '0120000000000000000000000000000000000000000000000000000000000000000000000000'


#mines the block
def compute_block_header(txids_in_block):
    difficulty = '0000ffff00000000000000000000000000000000000000000000000000000000'
    max_nonce = (2 ** 32) - 1

    #Version 4 byte little endian
    version = '04000000'
    #Previous Block 32 byte natural byte order, use fixed block 00000000000000000000a7cfc860d0488c8ad4a72b2de3ef1340a989a3fbd559
    prev_block = '59d5fba389a94013efe32d2ba7d48a8c48d060c8cfa700000000000000000000'
    #Merkle Root 32 byte natural byte order, of all transactions
    merkle_tx = compute_merkle_root(txids_in_block, False)
    #Time 4 bytes little endian (Unix timestamp)
    timestamp = int(time.time()).to_bytes(4, byteorder='little').hex()
    #Bits 4 bytes little endian, corresponds to the difficulty, this is '1f00ffff' before converting to little endian
    bits = 'ffff001f'
    for i in range(0, max_nonce):
        #Nonce 4 bytes little endian
        nonce = i.to_bytes(4, byteorder='little').hex()

        candidate_header = version + prev_block + merkle_tx + timestamp + bits + nonce
        candidate_header_hash = double_sha256(bytes.fromhex(candidate_header)).hex()
        candidate_header_hashrev = ''.join([candidate_header_hash[i:i+2] for i in range(0, len(candidate_header_hash), 2)][::-1])
        if(int(candidate_header_hashrev, 16) < int(difficulty, 16)):
            
            print("candidate header raw:", candidate_header)
            print("candidate header hash:", candidate_header_hash)
            print("candidate header rev:", candidate_header_hashrev)
            print("candidate header int:", int(candidate_header_hash, 16))
            return candidate_header

    print("not under required difficulty")
    return None

# tests
# der_sig = "304402202c31662db969bbeb98e3a759583833a85f76de94253d3bcd1e551b38e49bff380220071d7b4a47a6ec28f2fa191aa606c32506bd1c8b0b89482c965870717145cc6b01"
# print(der_to_rawsig(der_sig))

# der_sig1 = "3045022100e01f5b99d49e6fe3a7cfe67a2236522f7f3d3a440b4e58dc5b385517774afd0e02204754713454ef370db5d81a0762c474f7c25475a5c95dcd107939a4fe1312ab7b"
# print(der_to_rawsig(der_sig1))

# der_sig2 = "3045022100e295f9aedc4673d0abefc35ec5b9387a46453be1278e132045d7aeeb37474d11022039ae4e3070de9cebef749c8afa2cc6e31e055de7ec0c1ebcbff813d0ca9c5d9e01"
# print(der_to_rawsig(der_sig2))