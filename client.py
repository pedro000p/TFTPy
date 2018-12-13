#!/usr/bin/env python3

from docopt import docopt
from textwrap import dedent
from socket import *  # For socket
import socket  # For sockets
import sys  # For exit
import struct  # For packets
import re  # For regular expressions
from time import sleep  # For waiting for server reply
import os.path  # Check file integrity
from cmd import Cmd  # Use of prompt
import tftp


mode = b'octet\0'

ct4 = 0
ct3 = 0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

doc = """
TFTPy: A client and Server using TFTP protocol. Written in Python 3 by Pedro Pereira & Pedro Lourenço (11/06/17)

Usage: 
    client.py (get|put) [-p <serv_port>] <server> <source_file> [<dest_file>]
    client.py [-p <serv_port>] <server>

Options:
  -v, --version
  -h, --help                          show this help message and exit        
  -p <serv_port>, --port=<serv_port>  list only ports [default: 69]
  <dest_file>                         name file
"""

usage = """client.py [-h]
           client.py (get|put) [-p serv_port] <server> <source_file> [<dest_file>]
           client.py [-p serv_port] <server>
"""

args = docopt(doc)
port = args['--port']
host = args['<server>']
addr = host, port


RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'
DIR = b'\x00\x06'

BLK0 = b'\x00\x00'
BLK1 = b'\x00\x01'


ct = 0
if args['<server>'] == 'get':
    ct += 1
if args['<server>'] == 'put':
    ct += 1
if ct == 1:
    print(usage)
    sys.exit()


host_arg = args['<server>']
ip_verify = args['<server>'].split('.')
if len(ip_verify) == 1:
    pass
if len(ip_verify) == 4:
    verify_ip = tftp.is_valid_ipv4_address(args['<server>'])
    if verify_ip == False:
        print("The inserted server don't have a valid IP address.")
        sys.exit()
if 4 > len(ip_verify) > 1:
    print("The inserted server don't have a valid IP address.")
    sys.exit()


port = int(args['--port'])
addr = host, port

naming_file = args['<dest_file>']
path = args['<source_file>']


path = './'
mode = b'octet\0'
ct_args = 0

if args['get']:
    op = 1
    filename = args['<source_file>']
    if not args['<dest_file>']:
        cheking, filetoW = tftp.file_verify(args['<source_file>'])
        if cheking == True:
            print("File '%s' already exists locally! [error 6] Give a [remote_file] name." % (filetoW.decode()))
            raise SystemExit 
    filename = filename.encode()
    filename += b'\0'
    if args['<dest_file>']:
        cheking2, filetoW2 = tftp.file_verify(args['<dest_file>'])
        if cheking2 == True:
            print("File '%s' already exists locally! [error 6] Give another [remote_file] name." % (filetoW2.decode()))
            raise SystemExit 
        filename += naming_file.encode()
    packet = tftp.pack_R_W(op, filename, mode)

if args['put']:
    op = 2
    filename = args['<source_file>']
    
    file, namefile = tftp.file_verify(filename)
    if file == True:
        filena = namefile
        filena += b'\0'
    if file != True:
        print("File %s not found! [error 1]" % args['<source_file>'])
        sys.exit()
    if args['<dest_file>']:
        filena += naming_file.encode()
    packet = tftp.pack_R_W(op, filena, mode)


class MyPrompt(Cmd):

    def do_get(self, args: list = sys.argv, addr = addr):
        
        args2 = args.split()
        
        if len(args2) == 0:
            print('usage: get ficheiro_remoto [ficheiro_local]')
            prompt = MyPrompt(host, port)
            prompt.prompt = 'tftp client> '
            prompt.cmdloop()
        if len(args2) == 1:
            filename = args2[0].encode()
            filename += b'\0'
            chekingG, filetoWG = tftp.file_verify(args2[0])
            if chekingG == True:
                print("File '%s' already exists! [error 6] Give a [remote_file] name." % (filetoWG.decode()))
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()
            
        if len(args2) == 2:
            filename = args2[0].encode()
            filename += b'\0'
            filename += args2[1].encode()
            name_to_save = args2[1]
            chekingG2, filetoWG2 = tftp.file_verify(args2[1])
            if chekingG2 == True:
                print("File '%s' already exists! [error 6] Give another [remote_file] name." % (filetoWG2.decode()))
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()
      
        op = 1
        ct_EX = 0
        file = tftp.pack_R_W(op, filename, mode)
        ck_ping = tftp.ch_conn(addr[0])

        if ck_ping == True:
            s.sendto(file, addr)
        
        try:
            while 1:

                data, addr = s.recvfrom(16384)
                s.settimeout(10)
                pack_type = tftp.check_pack(data)
                host1 = addr[0]
                fqdn = getfqdn(host1)
                ct_EX += 1
                if ct_EX == 1:
                    print("Exchanging files with '%s' ('%s')" % (fqdn, host1))
                port1 = addr[1]
                if data == 'end':
                    s.settimeout(10)


                if pack_type == DAT:
         
                    blk = data[2:4]
                    if len(args2) == 2:
                        if blk == BLK1:
                            ack_send, namesaved = tftp.treat_DAT1(data, path, args2[1])
                   
                            s.sendto(ack_send, addr)
                        if blk > BLK1:
                            ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                    
                            s.sendto(ack_send, addr)
                    else:
                        if blk == BLK1:
                            ack_, namesaved = tftp.treat_DAT1(data, path, args2[0])
                            s.sendto(ack_, addr)
                        if blk > BLK1:
                            ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                            s.sendto(ack_, addr)

                if pack_type == ACK:
              
                    op = 3
                    ct4 += 1
                    if ct4 == 1:
                        fi = tftp.open_file(namefile)
                        blocks=tftp.chunks(fi, 512)
                    inf = next(blocks,'end')
                    file = str(file).strip("[]")
                    if inf == 'end':
                        print("Sent file '%s' %d bytes" % (namefile.decode(), fi))
                        ct4 = 0
                        s.settimeout(10)
                        continue
                    numb_blk = next(blocks,'end')
              
                    packet = tftp.pack_3_(op, numb_blk, inf)
                    s.sendto(packet, addr)
        

                # LEITURA DO PACOTE 5 (ERR)
                if pack_type == ERR:
        
                    info = tftp.unpack_err(data)
                    op, err, msg = info
                    print('%s' % (msg))
                    prompt = MyPrompt(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()
                    continue

        except ConnectionRefusedError:

            print("Couldn't open the socket for the host %s with IP address '%s'." % (fqdn, host))
            print("Setting timeout. Trying...")
            s.connect(addr)
            ct = 0
            
            s.connect(addr)
            s.settimeout(10)

        except timeout:           
      
            if pack_type >= BLK1:
                print("Backing to the prompt with the host address '%s'." % (host1))
                s.settimeout(5)
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()
            else:
                print('Trying again...')
                ct += 1
                s.connect(addr)
                s.settimeout(10)
                if ct == 2:
                    print("Can't connect!")
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()
        

    def do_put(self, args: list = sys.argv, addr = addr):
        
        args2 = args.split()
        
        if len(args2) == 0:
            print('usage: put ficheiro_local [ficheiro_remoto]')
            prompt = MyPrompt()
            prompt.prompt = 'tftp client> '
            prompt.cmdloop()

        if len(args2) == 1:
            filename=args2[0].encode()
            filename += b'\0'
            file_to_verify = args2[0]
                    
        if len(args2) == 2:
            filename = args2[0].encode()
            filename += b'\0'
            filename += args2[1].encode()
            file_to_verify = args2[0]
        ct4 = 0
        op = 2
        ct_EX = 0
        ct1 = 0
        ck_ping = tftp.ch_conn(addr[0])
        if ck_ping == True:
            file, namefile = tftp.file_verify(file_to_verify)

        if file == True:
            packet = tftp.pack_R_W(op, filename, mode)
            s.sendto(packet,addr)            

        if file != True:
            print("File not found! [error 1]")
            prompt = MyPrompt(host, port)
            prompt.prompt = 'tftp client> '
            prompt.cmdloop()
    
        try:
            while 1:
                data, addr = s.recvfrom(8192)
                blk = data[2:4]
                s.settimeout(10)
                pack_type = tftp.check_pack(data)
                host1 = addr[0]
                fqdn = getfqdn(host1)
                ct_EX += 1
                if ct_EX == 1:
                    print("Exchanging files with '%s' ('%s')" % (fqdn, host1))
                port1 = addr[1]
                if data == '':
                    s.settimeout(5)


                if pack_type == DAT:
                    blk = data[2:4]
                    if len(args2) == 2:
                        if blk == BLK1:
                            ack_send, namesaved = tftp.treat_DAT1(data, path, args2[1])
                        
                            s.sendto(ack_send, addr)
                        if blk > BLK1:
                            ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                            s.sendto(ack_send, addr)

                    else:
                        if blk == BLK1:
                            ack_, namesaved = tftp.treat_DAT1(data, path)
                            s.sendto(ack_, addr)
                        if blk > BLK1:
                            ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                            s.sendto(ack_, addr)
                          

                if pack_type == ACK:
               
                    op = 3
                    ct4 += 1
                    if ct4 == 1:
                        fi = tftp.open_file(namefile)
                        blocks = tftp.chunks(fi, 512)
                    inf = next(blocks,'end')
                    file = str(file).strip("[]")
                    if inf == 'end':
                        print("Sent file '%s' %d bytes" % (namefile.decode(), len(fi)))
                        ct4 = 0
                        ct_EX = 0
                        s.settimeout(5)
                        continue
                    numb_blk = next(blocks,'end')
                
                    packet = tftp.pack_3_(op, numb_blk, inf)
                    s.sendto(packet, addr)
        

                # LEITURA DO PACOTE 5 (ERR)
                if pack_type == ERR:
                 
                    info = tftp.unpack_err(data)
                    op, err, msg = info
                    print('%s' % (msg))
                    ct_EX = 0
                    prompt = MyPrompt(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()
                    continue

        
        except ConnectionRefusedError:


            print("Couldn't open the socket for the host %s with IP address '%s'." % (fqdn, host))
            print("Setting timeout. Trying...")
            s.connect(addr)
            ct = 0
            
            s.connect(addr)
            s.settimeout(10)

        except timeout:           
       
            if pack_type >= BLK1:
                print("Backing to the prompt with the host address '%s'." % (host1))
                s.settimeout(5)
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()

            else:
                print('Trying again...')
                ct += 1
                s.connect(addr)
                s.settimeout(10)
                if ct == 2:
                    print("Can't connect!")
                prompt = MyPrompt(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()


    def do_dir(self, args = sys.argv, addr = addr):
        """Do dir in connected server"""
             
        if len(args) == 0:
            diiir_list = ''
            blk_dir = []
            send_dir = tftp.dir_pack_send()
            s.sendto(send_dir, addr)
            ct_EX = 0
            while 1:
                data, addr = s.recvfrom(8192)
                s.settimeout(10)
                pack_type = tftp.check_pack(data)
                blk = data[2:4]
                data_d = data[4:]
                host1 = addr[0]
                fqdn = getfqdn(host1)
                port1 = addr[1]
                if data == '':
                    s.settimeout(10)
                if pack_type == DAT:
                    diiir_list += data_d.decode()
                    blk_dir.append(blk)
                    blk2 = str(blk)
                    blk3 = blk2.strip("b'\\x0'")
                    blk4 = int(blk3)
                    op = 6
                    dir_send = tftp.pack_6_dir(op, blk4)
                    s.sendto(dir_send, addr)
                    if len(data) < 512:
                        
                        tftp.show_dir(diiir_list)
                        prompt = MyPrompt(host, port)
                        prompt.prompt = 'tftp client> '
                        prompt.cmdloop()
     
        else:
            print('usage: dir')


    def do_help(self, args):
        """show commands"""
        print("Commands:\n")
        print("get remote_file [local_file]\t-\tget a file from server and save it as local_file")
        print("put local_file [remote_file]\t-\tsend a file to server and store it as remote_file")
        print("dir                         \t-\tobtain a listing of remote files")
        print("quit                        \t-\texit TFTP client")
        print("help                        \t-\tshow commands\n")


    def do_quit(self, args):
        """Quits the program."""
        print("Exiting TFTP client..")
        print("Goodbye!")
        raise SystemExit


# Inicialização da prompt com [-p serv_port] <server>

if args['put'] == False:
    ct_args += 1

if args['get'] == False:
    ct_args += 1

if args['<source_file>'] == None:
    ct_args += 1

if args['<dest_file>'] == None:
    ct_args += 1

if ct_args == 4:    
    prompt = MyPrompt(host, port)
    prompt.prompt = 'tftp client> '
    prompt.cmdloop('Starting prompt...')


s.connect((host, port))
ck_ping = tftp.ch_conn(addr[0])
if ck_ping == True:
    s.sendto(packet, addr)
else:
    print(ck_ping)
    raise SystemExit


ct_EX = 0
blk = 0
ct4 = 0
ct3 = 0
buf = 65536

if __name__ == '__main__':

    while True:

        try:            
            data, addr = s.recvfrom(buf)
            s.settimeout(20)
            pack_type = tftp.check_pack(data)
            op = data[:2]
            bloco = data[2:4]
            host1 = addr[0]
            fqdn = getfqdn(host)
            ct_EX += 1
            if ct_EX == 1:
                print("Exchanging files with '%s' ('%s')" % (fqdn, host1))
            port1 = addr[1]
      

            # LEITURA DO PACOTE 1 (RRQ)
            if pack_type == RRQ:
                ack_send = tftp.treat_RQQ(data)
                if len(ack_send) == 2:
                    _send, file = ack_send
                    s.sendto(_send, addr)
                if len(ack_send) == 3:
                    send_er, msg, err = ack_send
                    s.sendto(send_er, addr)
           

            # LEITURA DO PACOTE 2 (WRQ)
            if pack_type == WRQ:
    
                ack_send,file=tftp.treat_WRQ(data)
                s.sendto(ack_send, addr)

            # LEITURA DO PACOTE 3 (DAT)
            if pack_type == DAT:
      
                blk = data[2:4]
                if args['<dest_file>']:
                    if blk == BLK1:
                        ack_send, namesaved = tftp.treat_DAT1(data, path, args['<dest_file>'])
                    
                        s.sendto(ack_send, addr)
                    if blk > BLK1:
                        ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
              
                        s.sendto(ack_send, addr)
                        if not data:
                            get_size = os.path.getsize(namesaved)
                            print('get size', get_size)
                else:
                    if blk == BLK1:
                            ack_, namesaved = tftp.treat_DAT1(data, path, args['<source_file>'])
                            s.sendto(ack_, addr)
                    if blk > BLK1:
                        ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                        s.sendto(ack_, addr)
                    if not data:
                        get_size = os.path.getsize(namesaved)
                        print('get size', get_size)

            # LEITURA DO PACOTE 4 (ACK)
            if pack_type == ACK:
         
                op = data[:2]
                blk = data[2:]
    
                if blk <= BLK1:

                    if blk == BLK0:
                        ct4 += 1
                        file_open = tftp.open_file(filename)
             
                        gen = tftp.chunks(file_open, 512)
                        dat = next(gen, 'end')
              
                        if dat == 'end':                            
                            ct4 = 0
                            ct_EX = 0
                            s.settimeout(5)
                            continue
                        op = 3
                        blocks = next(gen, 'end')
                        packet_DAT = tftp.pack_3_(op, blocks, dat)
                        s.sendto(packet_DAT, addr)
                        continue

                    if blk == BLK1:
                        if ct4 == 0:
                            file_open = tftp.open_file(filename)
                            gen = tftp.chunks(file_open, 512)
                            dat = next(gen, 'end')
                    
                            if dat == 'end':
                                print("File '%s' sended with %d bytes" % (filename, len(file_open) ))
                                ct4 = 0
                                ct_EX = 0
                                s.settimeout(5)
                                continue
                            op = 3
                            blocks = next(gen, 'end')
                            packet_DAT = tftp.pack_3_(op, blocks, dat)
                            s.sendto(packet_DAT, addr)
                            continue

                        else:
                            dat = next(gen, 'end')
                            if dat == 'end':
                                print("File '%s' sended with %d bytes" % (filename, len(file_open)))
                                ct4 = 0
                                ct_EX = 0
                                s.settimeout(5)
                                continue
                            blocks = next(gen, 'end')
                            op = 3
                            packet_DAT = tftp.pack_3_(op, blocks, dat)
                            s.sendto(packet_DAT, addr) 
                            continue

                if blk > BLK1:
                    dat = next(gen, 'end')
                    if dat == 'end':
                        print("File '%s' sended with %d bytes " % (filename, len(file_open)))
                        ct4 = 0
                        s.settimeout(5)
                        continue
                    blocks = next(gen, 'end')
                    op = 3
                    packet_DAT = tftp.pack_3_(op, blocks, dat)
                    s.sendto(packet_DAT, addr)
                    continue
                

            # LEITURA DO PACOTE 5 (ERR)
            if pack_type == ERR:
           
                info = tftp.unpack_err(data)
                op, err, msg = info
                print('%s' % (msg))
                s.settimeout(10)
                continue

            if not data:
                s.settimeout(5)
                break


        except ConnectionRefusedError:

            print("Couldn't open the socket for the host %s ." % (host))
            print("Setting timeout. Trying...")
            s.connect(addr)
            ct = 0
            
            s.connect(addr)
            s.settimeout(10)

        except timeout:     
            
            if pack_type >= BLK1:
                print("Turning off the connection with the host '%s'." % (host))
                s.settimeout(5)
                break
            else:
                print('Trying again...')
                ct += 1
                s.connect(addr)
                s.settimeout(5)
                if ct == 2:
                    print("Can't connect!")
                    break

        except KeyboardInterrupt:
            print("Exiting TFTP client..")
            print("Goodbye!")
            break
    s.close()
