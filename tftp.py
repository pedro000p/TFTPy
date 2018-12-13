#!/usr/bin/env python3

from io import IOBase
from textwrap import dedent
from socket import *  # For socket
import socket  # For sockets
import sys  # For exit
import struct  # For packets
import re  # For regular expressions
from time import sleep  # For waiting for the server reply
import os.path  # Check file integrity
import tftp
import random, string
import os


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
BUF = 1048576

ct = 0


def chunks(file, n):
    "Yield successive n-sized chunks from readed file"
    
    blk = 0
    for i in range(0, len(file), n):
        blk += 1
        yield file[i:i+n]
        yield blk


def pack_R_W(op, filename, mode):
    "Constrói packs do tipo RRQ e WRQ"
    
    fmt = '!H{}s6s'.format(len(filename), len(mode))
    packet_fmt = struct.pack(fmt, op, filename, mode)
    return packet_fmt


def pack_3_(op, blk, dat):
    "Constrói pack do tipo DAT"
    "Formato: op(2bytes) <> blk(2bytes) <> dat(n-bytes)"

    op = 3
    if type(dat) == str:
        dat = dat.encode()
        dat += b'\0'
    else:
        dat += b'\0'
    fmt = '!HH{}s'.format(len(dat))
    packet_fmt = struct.pack(fmt, op, blk, dat)
    return packet_fmt


def pack_4_(op, blk):
    "Constrói pack do tipo ACK"
    "Formato: op(2bytes) <> blk(2bytes)"

    op = 4
    fmt = '!HH'.format()
    packet_fmt = struct.pack(fmt, op, blk)
    return packet_fmt


def pack_err(op, err, msg):
    "Constrói pack do tipo ERR"
    "Formato: op(2bytes) <> err(2bytes) <> err_msg(n-bytes)"

    if isinstance(msg, list):
        msg = msg[0]
        if isinstance(msg, str):
            msg = msg.encode()
    if isinstance(msg, str):
        msg = msg.encode()
    msg += b'\0'
    op = 5
    fmt = '!HH{}s'.format(len(msg))
    packet_fmt = struct.pack(fmt, op, err, msg)
    return packet_fmt


def unpack_err(pack):
    "Descompacta pack do tipo ERR"

    msg = pack[4:]
    fmt = '!HH{}s'.format(len(msg))
    op, err, msg = struct.unpack(fmt, pack)
    msg = msg.decode().strip('\x00')
    lista = op, err, msg
    return lista


def unpack_R_W(pack):
    "Descompacta packs do tipo RRQ e WRQ"

    file = pack[2:-6]  # File received
    mode = pack[-6:]  # Mode received
    opcode = pack[:2]  # Opcode received

    fmt = '!H{}s6s'.format(len(file), len(mode))
    opcode, fileS, mode = struct.unpack(fmt, pack)
    fileS = file.decode('utf-8')  # File decoded from bytes
    modeS = mode.decode('utf-8')  # Mode decoded from bytes
    stripped = '\x00-\x01-\x02-\x03-\x04'
    fileDES = fileS.strip(stripped)
    fileDesF = fileDES.split('\x00')

    if len(fileDesF) == 2:
        f_rqq = fileDesF[0]
        f_toWrite = fileDesF[1]
        modeDES = modeS.strip(stripped)
        lista = opcode, f_rqq, f_toWrite, modeDES
        return lista

    else:
        modeDES = modeS.strip(stripped)
        lista = opcode, fileDesF, modeDES
        return lista

def unpack_dat(pack):
    "Descompacta pack do tipo DAT"    

    pat = re.compile(b'(^[\x00-\x05]{1,2})')
    chk_type = re.search(pat, pack)
    verify = chk_type.group()

    if verify == b'\x00\x03':
        data = pack[4:]        
        fmt = '!HH{}s'.format(len(data))
        op, blk, datal = struct.unpack(fmt, pack)
        data_con = datal.strip(b'\x00')
        data_c = data_con.decode('utf-8', 'ignore')
        lista = op, blk, data_c
        return lista


def check_pack(data):
    "Determina o tipo de pack: RRQ <> WRQ <> DAT <> ACK <> ERR"

    RRQ = b'\x00\x01'
    WRQ = b'\x00\x02'
    DAT = b'\x00\x03'
    ACK = b'\x00\x04'
    ERR = b'\x00\x05'
    DIR = b'\x00\x06'

    pat_all = re.compile(b"(^[\x00-\x05].)")
    chek = re.search(pat_all, data)
    
    if chek == None:
        return data
    else:
        check = chek.group()

    if check == RRQ:
        out = "Packet received RRQ: "
    if check == WRQ:
        out = "Packet received WRQ: "
    if check == DAT:
        out = "Packet received DAT: "
    if check == ACK:
        out = "Packet received ACK: "
    if check == ERR:
        out = "Packet received ERR: "
    if check == DIR:
        out = "Treating DIR"
    return check


def file_verify(file_to_chk):
    "Faz a verificação da existência do ficheiro e diz o seu tamanho em bytes"    
    
    if isinstance(file_to_chk, list):
        file_to_chk = str(file_to_chk).strip("[]''")

    if isinstance(file_to_chk, str): 
        file_to_chk=file_to_chk.encode()

    if os.path.isfile(file_to_chk) == True:
        f1_= open(file_to_chk, 'rb')
        f_ = f1_.read(8192)
        filesize_send = len(f_)
        print("File '{}' have {} bytes.".format(file_to_chk.decode(), filesize_send))
        return True, file_to_chk

    else:
        msg = b'File not found! [error 1]'
        op = 5
        err = 1
        err_send = tftp.pack_err(op, err, msg)
        not_exist = False
        return not_exist, err_send


def open_file(filename):
    "Abre um ficheiro para ser enviado em packs"

    try:        
        pat_all = re.compile(b"([\x00-\x05])")

        if isinstance(filename, bytes) == False:
            filename = filename.encode()
        check = re.search(pat_all, filename).group()

        if check:
            file_O, file_w = filename.split(b'\x00')
            file = file_O
            f_ = open(file, 'rb').read()
            return f_

        else:
            file = filename
            f_ = open(file, 'rb').read()
            return f_


    except FileNotFoundError:
        print('File not found! [error 1]')

        op = 5
        error = 1
        msg = b'File not found! [error 1]'
        pac_err = pack_err(op, error, msg)
        return pac_err


    except UnboundLocalError:

        file = filename
        f_ = open(file, 'rb').read()
        return f_       


    except AttributeError:
        if filename == None:
            print('File not found! [error 1]')

            op = 5
            error = 1
            msg ='File not found! [error 1]'
            pac_err = pack_err(op, error, msg)
            return pac_err

        else:
            file = filename
            f_ = open(file, 'rb').read()
            return f_

        
def treat_RQQ(data):
    "Tratamento / Leitura do pack do tipo RRQ"

    lista = tftp.unpack_R_W(data)

    if len(lista) == 3:
        op, file, mode = lista
        file = file

    if len(lista) == 4:
        op, file, name_f, mode = lista
        
    IF_file, file = file_verify(file)

    if IF_file == True:
        
        file_O = open_file(file)
        print("Preparing '%s'." % (file))        
        return  file_O, file

    else:
        err = 1
        msg = b'File not found! [error 1]'
        send_err = tftp.pack_err(op, err, msg)
        return send_err, msg, err


def treat_RQQ_srv(data, path):
    "Tratamento / Leitura do pack do tipo RRQ"

    lista = tftp.unpack_R_W(data)
    path = path.encode()

    if len(lista) == 3:
        op, file, mode = lista
        file = str(file)
        file1 = file.strip("b'[]'")
        file2 = file1.encode()
        file = path + file2

    if len(lista) == 4:
        op, file, name_f, mode = lista        
        file = str(file)
        file1 = file.strip("b'[]'")
        file2 = file1.encode()        
        file = path + file2

    IF_file, file = file_verify(file)

    if IF_file == True:        
        file_O = open_file(file)
        print("Preparing '%s'." % (file))        
        return  file_O, file

    else:
        err = 1
        msg = b'File not found! [error 1]'
        send_err = tftp.pack_err(op, err, msg)
        return send_err, msg, err



def treat_WRQ_srv(data, path):
    "Tratamento / Leitura do pack do tipo WRQ"

    lista = tftp.unpack_R_W(data)
    path = path.encode()

    if len(lista) == 3:
        op, file, mode = lista
        file = str(file)
        file1 = file.strip("b'[]'")
        file2 = file1.encode()
        file = path + file2
        IF_file, namefile = file_verify(file)

        if IF_file == True:
            op = 5
            err = 6
            msg = b'File already exists! [error 6]'
            send_err = tftp.pack_err(op, err, msg)
            return send_err, err

        else: 
            op = 4
            blk = 0 
            ack_toSend = tftp.pack_4_(op, blk)
            return ack_toSend, file

    if len(lista) == 4:
        op, file, name_f, mode = lista
        file = str(file)
        file1 = file.strip("b'[]'")
        file2 = file1.encode()
        name_f = lista[2]
        name_f1 = str(name_f)
        name_f2 = name_f1.strip("b'[]'")
        name_f3 = name_f2.encode()
        file_tosave = path + name_f3

        IF_file, namefile = file_verify(file_tosave)

        if IF_file == True:
            op = 5
            err = 6
            msg = b'File already exists! [error 6]'
            send_err=tftp.pack_err(op, err, msg)
            return send_err, msg, err

        else:
            op = 4
            blk = 0 
            ack_toSend = tftp.pack_4_(op, blk)
            return ack_toSend, file2, file_tosave

def treat_WRQ(data):
    "Tratamento / Leitura do pack do tipo WRQ"

    lista = tftp.unpack_R_W(data)
    
    if len(lista) == 3:
        op, file, mode = lista
        file = lista[1]
        IF_file, namefile = file_verify(file)

        if IF_file == True:
            op = 5
            err = 6
            msg = b'File already exists! [error 6]'
            send_err = tftp.pack_err(op, err, msg)
            return send_err, err

        else: 
            op = 4
            blk = 0 
            ack_toSend = tftp.pack_4_(op, blk)
            return ack_toSend, file

    if len(lista) == 4:
        op, file, name_f, mode = lista
        file = lista[1]
        name_f = lista[2]
        IF_file, namefile = file_verify(name_f)

        if IF_file == True:
            op = 5
            err = 6
            msg = b'File already exists! [error 6]'
            send_err=tftp.pack_err(op, err, msg)
            return send_err, msg, err

        else:
            op = 4
            blk = 0 
            ack_toSend = tftp.pack_4_(op, blk)
            return ack_toSend, file, name_f


def treat_DAT1(data, path, filename_tosave):
    "Tratamento / Leitura do pack do tipo DAT após RRQ"
  
    dat = unpack_dat(data)
    op, blk, dat_r = dat
    dat_r = dat_r.encode()

    if isinstance(filename_tosave, str):
        filename_tosave = filename_tosave.encode()
    
    file_write = open(filename_tosave, 'wb').write(dat_r)
    print("File created --> %s" % (filename_tosave.decode()))
    op = 4
    send_ack = pack_4_(op, blk)    
    return send_ack, filename_tosave


def treat_DAT1_srv(data, filename_tosave):
    "Tratamento / Leitura do pack do tipo DAT após RRQ"
  
    dat = unpack_dat(data)
    op, blk, dat_r = dat
    dat_r = dat_r.encode()
    
    if isinstance(filename_tosave, str):
        filename_tosave = filename_tosave.encode()
        
    file_write = open(filename_tosave, 'wb').write(dat_r)
    print("File created --> %s" % (filename_tosave.decode()))
    op = 4
    send_ack = pack_4_(op, blk)    
    return send_ack, filename_tosave


def treat_DAT2(data, filename_tosave):

    dat = tftp.unpack_dat(data)
    op, blk, dat_r = dat
    dat_r = dat_r.encode()    
    file_write = open(filename_tosave, 'ab').write(dat_r)    
    op = 4
    send_ack = tftp.pack_4_(op, blk)
    return send_ack, filename_tosave


def treat_ERR(data):
    "Tratamento / Leitura do pack do tipo ERR"
    print('ERR received...')

    ERR1 = b'\x00\x01'
    ERR2 = b'\x00\x02'
    ERR3 = b'\x00\x03'
    ERR4 = b'\x00\x04'
    ERR5 = b'\x00\x05'
    ERR6 = b'\x00\x06'
    ERR7 = b'\x00\x07'
    ERR8 = b'\x00\x08'

    op, err = data

    if err == ERR1:
        msg = 'File not found'
        return msg
    if err == ERR2:
        msg = 'Access violation'
        return msg
    if err == ERR3:
        msg = 'Disk full or allocation exceeded'
        return msg
    if err == ERR4:
        msg = 'Ilegal TFTP operation'
        return msg
    if err == ERR5:
        msg = 'Unknown transfer ID'
        return msg
    if err == ERR6:
        msg = 'File already exists'
        return msg
    if err == ERR7:
        msg = 'No such user'
        return msg
    if err == ERR8:
        msg = 'Terminate transfer due to option negotiation'
        return msg


def is_valid_ipv4_address(address):

    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # No inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # Not a valid address
        return False

    return True


def pack_6_dir(op, blk):
    "Constrói pack do tipo ACK para DIR"
    "Formato: op(2bytes) <> blk(2bytes)"

    op = 6
    fmt = '!HH'.format()
    packet_fmt = struct.pack(fmt, op, blk)
    return packet_fmt


def dir_unpack(pack):
    "Descompacta pack do tipo DIR"

    op = pack[:2]
    fmt = '!HH{}s'.format(len(msg))
    op, err, msg = struct.unpack(fmt, pack)
    msg = msg.decode().strip('\x00')
    lista = op, err, msg
    return lista


def make_dir(path):
    lista_dir = os.popen('ls -lah %s' % (path))
    return lista_dir


def dir_pack_send(filename = b''):
    "Constrói pacotes DIR"

    filename += b'\0'
    op = 6
    mode = b'octet\0'
    fmt = '!H{}s6s'.format(len(filename), len(mode))
    packet_fmt = struct.pack(fmt, op, filename, mode)
    return packet_fmt


def show_dir(dir_show):
    "Faz o DIR após a sua recepção"
    
    dir_msg2 = dir_show.split('\n')
    for i in dir_msg2:
        print(i)


def pack_3_dir(op, blk, dat):
    "Constrói pack do tipo DAT"
    "Formato: op(2bytes) <> blk(2bytes) <> dat(n-bytes)"

    op = 3
    if type(dat) == str:
        dat = dat.encode()
        dat += b'\0'

    else:
        dat += b'\0'
    fmt = '!HH{}s'.format(len(dat))
    packet_fmt = struct.pack(fmt, op, blk, dat)
    return packet_fmt


def ch_conn(host):

    pat = re.compile("([0-9] received)")
    ping = os.popen('ping -c 2 %s' % host).read()
    pat1 = re.search(pat, ping).group()
    if pat1 == '0 received':
        msg = "Cant connect with '%s' " % (host)
        return msg
    else:
        return True
