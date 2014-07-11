#!/usr/bin/env python

#=============================================================================
#
# File Name            : Main.py
# Author               : Pekeinfo <pekeinfo@gmaill.com>
# Creation Date        : Jul 2014
#
#
#
#=============================================================================
#
# PRODUCT            : Peid Signature to Yara 
# ROLE               : transform signature peid to Yara 
#
#
# DEPENDANCE SYS.    : os,sys,datatime
#
# ---------------------------------------------------------------------------
#
#=============================================================================


import os
import sys


from datetime import datetime 
today = datetime.now() #fecha actual
date = today.strftime("%Y/%m/%d")

author = "GuillermoC"

def read_db(path):
    fil = open(path,"r")
    line = fil.read().replace("\r",'').split("\n")
    lista = []
    lista.append([])
    lista.append([])
    for obj in line:
        if len(obj) >  2:
            if obj[0] == '[':
                lista[0].append(remove_non_ascii_1(remove_bad_char(obj)))
            if obj[0] == 's' and obj[1] == 'i' and obj[2] == 'g':
                lista[1].append(obj)
    for i in range(0,len(lista[0])):
        save_rule("tmp",lista[0][i],create_rule(lista[0][i],trasfor_signature(lista[1][i])))

def remove_non_ascii_1(text):
    return ''.join(i for i in text if ord(i)<128)

def remove_bad_char(name):
    #print name[1]
    if name[1].isdigit():
        print "is nameeeeee"
        name = "A"+name
    return name.replace('[','').replace(']','').replace('!','').replace('.','').replace(' ','').replace('-','').replace('(','').replace(')','').replace('>','').replace('<','').replace('\\','').replace('/','').replace('\'','').replace('&','').replace(':','').replace(',','').replace('+','').replace('^','').replace('?','').replace('~','').replace('$','').replace('`','').replace('*','').replace('%','').replace('#','').replace('@','').replace("\"",'')

def trasfor_signature(signature):
    buf = signature.split('=')
    return "{" + buf[1]+ " }"

def create_rule(name,signature):
    head = "rule "+name+" : "+name+"\n\
    {\n\
    meta:\n\
    author = \""+author+"\"\n\
    date = \""+date+"\"\n\
    description = \""+name+"\"\n\
    sample_filetype = \"exe\"\n\
    \nstrings:\n"

    foot = "condition:\n $signature\n}"
    regla = head + "$signature = "+ signature +"\n"+foot
    return regla    

def save_rule(path,file_name,regla):
    if not os.path.exists(path):
        print "Created->"+path
        os.makedirs(path)
    index = open(path+"/index.yar","a")
    if os.path.isfile(path +"/"+file_name+".yar"):
        print "#Duplic"
    else:
        fil = open(path+"/"+file_name+".yar","a")
        fil.write(regla)
        index.writelines("include \""+file_name+".yar\"\n")

if len (sys.argv) < 2:
    print "-Mode Use: "+sys.argv[0]+" <UserDB.txt>"
else:
    read_db(sys.argv[1])