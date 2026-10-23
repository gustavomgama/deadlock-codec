import struct, sys

data=open('build.bin','rb').read()

def read_varint(data, i):
    res=0; shift=0
    while True:
        if i>=len(data): break
        byte=data[i]; i+=1
        res |= (byte & 0x7f) << shift
        if not (byte & 0x80): break
        shift+=7
    return res,i

def decode(data, indent=0):
    i=0
    n=len(data)
    while i<n:
        tag,i=read_varint(data,i)
        field=tag>>3
        wire=tag&7
        prefix='  '*indent
        if wire==0:
            val,i=read_varint(data,i)
            print(f"{prefix}field {field} (varint): {val}")
        elif wire==2:
            length,i=read_varint(data,i)
            chunk=data[i:i+length]; i+=length
            try:
                s=chunk.decode('utf-8')
                if all(c.isprintable() or c in '\n\r\t' for c in s):
                    print(f"{prefix}field {field} (string): {s!r}")
                    continue
            except: pass
            print(f"{prefix}field {field} (bytes len={length}) -> nested:")
            try:
                decode(chunk, indent+1)
            except Exception as e:
                print(f"{prefix}  RAW: {chunk.hex()}")
        elif wire==1:
            val=struct.unpack('<d',data[i:i+8])[0]; i+=8
            print(f"{prefix}field {field} (fixed64): {val}")
        elif wire==5:
            val=struct.unpack('<f',data[i:i+4])[0]; i+=4
            print(f"{prefix}field {field} (fixed32): {val}")
        else:
            print(f"{prefix}unknown wire {wire}")
            break

decode(data)
