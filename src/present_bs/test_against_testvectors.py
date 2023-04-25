#!/usr/bin/python
import serial
import time
import sys

BLOCK_SIZE = 8
KEY_SIZE = 10
CPU_FREQUENCY = 125e6
BITSLICE_CNT = 32

BAUDRATE = 9600

if len(sys.argv) != 2:
    sys.exit("Usage: python3 ./test_against_testvectors.py [COMPORT, e.g. /dev/ttySX on WSL]")

COM_PORT = sys.argv[1]

ser = serial.Serial(COM_PORT, BAUDRATE, timeout=1)

# 3 pt
tv_pt = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,    
    0x45, 0x84, 0x22, 0x7B, 0x38, 0xC1, 0x79, 0x55,
]

# 3 keys
tv_key = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x3c, 0xf4, 0x00, 0xd8, 0x28, 0xf1, 0x08, 0x7a, 0x60, 0x26,
]

# 9 ct
tv_ct = [
    #  Pt 0, key 0
    0x45, 0x84, 0x22, 0x7b, 0x38, 0xc1, 0x79, 0x55, 
    #  Pt 1, key 0
    0x7b, 0x41, 0x68, 0x2f, 0xc7, 0xff, 0x12, 0xa1, 
    #  Pt 2, key 0
    0x9a, 0x36, 0xcc, 0x6f, 0xfd, 0x45, 0xdf, 0x4e, 
    #  Pt 0, key 1
    0x49, 0x50, 0x94, 0xf5, 0xc0, 0x46, 0x2c, 0xe7, 
    #  Pt 1, key 1
    0xd2, 0x10, 0x32, 0x21, 0xd3, 0xdc, 0x33, 0x33, 
    #  Pt 2, key 1
    0x4e, 0xa8, 0x43, 0x3c, 0xcf, 0x7f, 0x10, 0x25, 
    #  Pt 0, key 2
    0x5f, 0x46, 0x65, 0xf3, 0x2d, 0x76, 0xfe, 0x9a, 
    #  Pt 1, key 2
    0xb7, 0xf4, 0x2d, 0x2e, 0xe9, 0x48, 0x66, 0x23, 
    #  Pt 2, key 2
    0xd0, 0x44, 0x6a, 0x0a, 0xc9, 0x13, 0x35, 0xd4, 
]

TV_PT_COUNT = int(len(tv_pt) / BLOCK_SIZE)
TV_KEY_COUNT = int(len(tv_key) / KEY_SIZE)

debug = False

def unpack_le(s):
    return sum((s[i]) << (8 * i) for i in range(len(s)))

for tv in range(TV_KEY_COUNT):
    key = bytes(tv_key[tv*KEY_SIZE:(tv+1)*KEY_SIZE])
    print("== Key " + str(tv) + " = " + key.hex())
    

    # Send 16 plaintext blocks
    for j in range(BITSLICE_CNT):
        # Plaintext
        tv_idx = ((tv + j) % TV_PT_COUNT) * BLOCK_SIZE 
        pt = tv_pt[tv_idx:(tv_idx + BLOCK_SIZE)]
        
        # send one block        
        buf = str.encode("b")
        buf += bytes(pt)
        ser.write(buf)
        
        # read response
        rx = ser.read(2)
        
        if debug:
            print("[i] TX block {}: {} -> {}".format(j, buf.hex(), rx.hex()))
        else:
            print("[{}] ".format(j), end="")
    
    if debug == False:
        print()

    # Initial command & key
    buf = str.encode("e")
    buf += key
   
    if debug:
        print("TX: " + buf.hex())

    # Do operation
    ser.write(buf)

    # Get answer
    rx = ser.read(8)

    # duration in CPU cycles and seconds
    duration = unpack_le(rx)

    if debug:
        print("[i] RX: " + rx.hex())

    print("[+] Cycle count = " + str(duration) + " = " + str(duration/CPU_FREQUENCY) + " s")
    print("[+] Cycle count per block = " + str(duration/BITSLICE_CNT) + " = " + str(duration/CPU_FREQUENCY/BITSLICE_CNT) + " s")

    # Get ciphertext blocks
    for j in range(BITSLICE_CNT):
        # get one block        
        ser.write(str.encode("o"))
        
        # read response
        rx = ser.read(10)
        
        # Check result
        tv_idx = ((tv + j) % TV_PT_COUNT) * BLOCK_SIZE 
        tv_idx = tv_idx + tv*BLOCK_SIZE*TV_PT_COUNT
        
        r_ref = bytes(tv_ct[tv_idx:tv_idx+BLOCK_SIZE])
        r_comp = rx[:BLOCK_SIZE]
    
        if r_ref == r_comp:
            if debug:
                print("[OK] Result correct: " + ''.join('{:02x} '.format((x)) for x in r_comp).upper())
        else:
            print ("[FAILED]")
            print ("Got  : " + ''.join('{:02x} '.format((x)) for x in r_comp).upper())
            print ("Exp't: " + ''.join('{:02x} '.format((x)) for x in r_ref).upper())
            exit(0)
        
    print("[OK] Result correct")
    print()
    time.sleep(0.1)

ser.close()
