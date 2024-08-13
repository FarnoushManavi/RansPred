
# coding: utf-8

# In[ ]:


## extartct DOS header,COFF header, Optional header, entire header ##
import pefile
import os
from math import*

diraction = '.../data_address/...'
class_name_file = [ 'Benign','Ransomware']

for j in range(class_name_file.__len__()):
    listing = os.listdir(diraction + class_name_file[j])

    for infile in listing:
        try:
            pe = pefile.PE(diraction + class_name_file[j] +'/'+ infile)
            header = pe.header
            header = header[:1024]

            Bytes = []
            for byte in header:
                Bytes.append(byte)

            if len(Bytes) < 1024:
                for i in range(1024-len(Bytes)):
                    Bytes.append(0)

            # if length of header is more than 1024 bytes just keep the first 1024 bytes
            elif len(Bytes) > 1024:
                Bytes = Bytes[0:1024]

            # Extracting DOS_Header
            # DOS_Header is the first 64 Bytes of the file
            DOS_Header = Bytes[0:64]
            headerfile = open( 'Section Header/DOS_Header/'+ class_name_file[j] +'/'+infile, "wb")
            headerfile.write(bytes(DOS_Header))
            headerfile.close()

            # File_Header
            FileHeader_Offset = pe.DOS_HEADER.e_lfanew + pe.NT_HEADERS.sizeof()
            File_Header = Bytes[FileHeader_Offset:FileHeader_Offset + pe.FILE_HEADER.sizeof()]
            headerfile = open( 'Section Header/File_Header/'+ class_name_file[j] +'/'+infile, "wb")
            headerfile.write(bytes(File_Header))
            headerfile.close()

            # Optional_Header
            OptionalHeader_Offset = FileHeader_Offset + pe.FILE_HEADER.sizeof()
            Optional_Header = Bytes[OptionalHeader_Offset:OptionalHeader_Offset+224]
            headerfile = open('Section Header/Optional_Header/'+ class_name_file[j] +'/'+infile, "wb")
            headerfile.write(bytes(Optional_Header))
            headerfile.close()

        except Exception as e:
            print(infile)
            continue

