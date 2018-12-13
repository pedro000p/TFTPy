#!/usr/bin/env python3

import socket
from time import time, sleep
from textwrap import dedent
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
import sys
import struct
import os
import os.path
import re
import tftp
from docopt import docopt
from socketserver import BaseRequestHandler, ThreadingUDPServer
from threading import Thread

host = ''  # Symbolic name meaning all available interfaces

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
ThreadingUDPServer.allow_reuse_address = True

doc = """
TFTPy: The server side for the TFTP protocol. written in Python 3 by Pedro Pereira & Pedro Lourenço (11/06/17)

Usage: server.py [<directory>] [<port>]

Options:
  -h, --help
  [<directory>]             show this help [default: './']        
  <port>,   <port>=<port>   listening port [default: 69]
"""

args = docopt(doc)


if args['<directory>'] == None:
    args['<directory>'] = './'
if args['<port>'] == None:
    args['<port>'] = 69

try:
    v = int(args['<directory>'] )
    args['<port>'] = v
    args['<directory>'] = './'
    
except ValueError: 
    if len(sys.argv) == 1:
        args['<directory>'] = './'
    else:
        args['<directory>'] = sys.argv[1]

except IndexError:
    if len(sys.argv) == 0:
        args['<directory>'] = './'

port = int(args['<port>'])
hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
addr = host, port

RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'
DIR = b'\x00\x06'

BLK0 = b'\x00\x00'
BLK1 = b'\x00\x01'

path = args['<directory>']
path_chk = path[-1]

if not path_chk  == '/':
    print("The inserted path of directory don't end with slash '/'!\n Please do it to save correctly the files. ")
    raise SystemExit


### LIGAÇÕES UDP Bind ###

try:    
    s.bind(addr)
    print('Socket bind complete')
except socket.error as msg:
    print('Unable to bind to port %d' % (port))
    sys.exit()

ct6 = 0
ct4 = 0
ct = 0
buf = 65536

while True:
    
    try:
        print( "Waiting for requests on '%s' port '%s'\n" % (hostname, args['<port>']))
       
        data, addr = s.recvfrom(buf)
        host = addr[0]
        port = addr[1]       
        
        print ('received %s bytes from %s' % (len(data), addr))
                
        pack_type = tftp.check_pack(data)
        op = data[:2]
        bloco = data[2:4]
    

        # LEITURA DO PACOTE 1 (RRQ)
        if pack_type == RRQ:

            unpacked = tftp.treat_RQQ_srv(data, path)
            if len(unpacked) == 2:
                file_O, file = unpacked
                op = 3
                blocks = tftp.chunks(file_O, 512)
                info_file = next(blocks, 'end')
                if info_file == 'end':
                    file_out = file.rsplit(b'/')
                    print("The file requested, '%s' has been sent." % (file_out.decode()))
                info_file += b'\0'
                numb_blk = next(blocks, 'end')
                packet_DAT = tftp.pack_3_(op, numb_blk, info_file)
                filen = file.decode()
                s.sendto(packet_DAT, addr)
         
            if len(unpacked) == 3:
                send_err, msg, err = unpacked
                s.sendto(send_err, addr)
         

        # LEITURA DO PACOTE 2 (WRQ)        
        if pack_type == WRQ:
 
            output = tftp.treat_WRQ_srv(data, path)
            if len(output) == 2:
                ack_send, filen = output
                if filen == False:
                    print('File not found! [error 1]')
            if len(output) == 3:
                ack_send, filen, file_to_save = output
                if filen == False:
                    print('File not found! [error 1]')   
            
            s.sendto(ack_send, addr)


        # LEITURA DO PACOTE 3 (DAT)
        if pack_type == DAT:
   
            blk = data[2:4]

            if len(output) == 2:
                if blk == BLK1:
                    ack_send, namesaved = tftp.treat_DAT1_srv(data, filen)
                if blk > BLK1:
                    ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
            if len(output) == 3:
                if blk == BLK1:
                    ack_send, namesaved = tftp.treat_DAT1_srv(data, file_to_save)
                if blk > BLK1:
                    ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
            s.sendto(ack_send, addr)
           

        #LEITURA DO PACOTE 4 (ACK)       
        if pack_type == ACK:
      
            op = 3
            ct4 += 1
                        
            inf = next(blocks, 'end')
            file = str(file).strip("[]")
            
            if inf == 'end':
                file_out = filen.rsplit('/')
                print("The file requested, '%s' has been sent.\n" % (file_out[-1]))
                ct4 = 0
                continue
       
            numb_blk = next(blocks,'end')            
            packet = tftp.pack_3_(op, numb_blk, inf)
            s.sendto(packet, addr)
        

        # LEITURA DO PACOTE 5 (ERR)
        if pack_type == ERR:

            info = tftp.unpack_err(data)
            op, err, msg = info
            print('%s' % (err, msg))
            continue
            
        if pack_type == DIR:
            ct6 += 1
            path = args['<directory>']

            dir_srv = os.popen('ls -alh {}'.format(path)).read()
            if ct6 == 1:
                part_block = tftp.chunks(dir_srv, 512)
            
            inf = next(part_block, 'end')
            if inf == 'end':
                print('DIR sended')
                ct6 = 0
                continue
              
            numb_blk = next(part_block, 'end')
            op = 3
            dir_srv_S = tftp.pack_3_dir(op, numb_blk, inf)
            sent = s.sendto(dir_srv_S, addr)        
 
            
    except socket.timeout:
        print('Trying again...')
        ct += 1
        s.connect(addr)
        s.settimeout(10)        
        break

    except KeyboardInterrupt:
        print("Exiting TFTP server..")
        print("Goodbye!")
        break

s.close()
