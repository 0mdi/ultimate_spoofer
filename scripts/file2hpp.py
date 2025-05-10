import sys
import os
import binascii
import random

def bytes_from_file(filename, chunksize=8192):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                for b in chunk:
                    yield b
            else:
                break


if(len(sys.argv) < 2):
    print("invalid args")
    sys.exit(2)

binFile = sys.argv[1]

filePath = binFile[0 : binFile.rfind('\\') + 1]
fileName = binFile[binFile.rfind('\\') + 1 : ]
fileName = fileName[0 : fileName.find('.')]

outFileName = filePath + fileName + ".hpp"

print("Creating Shellcode from " + binFile + " to " + outFileName)

out = open(outFileName, 'w')
out.truncate()

xorKey = random.randrange(1, 254)

out.write("#pragma once\n")
out.write("#include <windows.h>\n")

out.write("static unsigned char " + "Xor_" + fileName + " = " + str(xorKey) + ";\n")

out.write("static unsigned char " + "Bin_" + fileName + " [] = {\n")


allbytes = list()


for b in bytes_from_file(binFile):
    allbytes.append(b)


for i in range(0, allbytes.__len__()):
    allbytes[i] ^= (xorKey)

    out.write(("{0:#0{1}x}".format(allbytes[i],4) + ""))
    if(i != allbytes.__len__() - 1):
        out.write(",")

out.write("\n};\n");


out.write("static int get" + fileName + "Len() {\n")
out.write("     return ARRAYSIZE("+ "Bin_" + fileName + ");\n");
out.write("}\n")

out.write("static unsigned char * get" + fileName + "() {\n")

str = ""
str += "    {\n"
str += "         for (int i = 0; i < ARRAYSIZE("+ "Bin_" + fileName + "); i++)\n"
str += "         {\n"
str += "             "+ "Bin_" + fileName + "[i] = " + "Bin_" + fileName + "[i] ^ " + "Xor_" + fileName  +";\n"
str += "         }\n"
str += "         return " + "Bin_" + fileName + ";\n"
str += "    }\n"
str += "    return nullptr;\n"
out.write(str)
out.write("}\n")
out.close()