#!/usr/bin/env python
#
# Base64cer.py
# Version 1.0
#   Codename: "Quick release with no PEP8 or QA"
#
# Authors:
#   David Pany - Mandiant (FireEye) - 2017
#       @davidpany
#   Daniel Bohannon - Mandiant (FireEye) - 2017
#       @danielhbohannon
#
# Description:
#   Base64cer.py will find all possible base64 and hex values of strings from a text file or standard input if no args are provided.
#   Encoded versions of both ASCII and UNICODE are provided.
#
#   Values output in parentheses () can change so you might not want to search for them, but the output
#   that is not in parentheses would make great search terms.
#
# Limitations:
#   Base64 and Hex keyword searching can easily be defeated if the decoded characters have unexpected case (upper/lower)
#
# Usage: 
#   python Base64cer.py
#       type in or paste in a string to see various permutations
#
#   python Base64cer.py inputfile.txt
#
#   License: 
#
#   Copyright 2017 David Pany
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

import sys
import re
import string
import base64

def base64ceString(InputString,VerboseTF):
    UnicodeMO = re.compile("(\x00)([^\x00])(\x00)([^\x00])(\x00)")
    
    if re.search(UnicodeMO,InputString):
        UnicodeString = InputString
        if UnicodeString[0] != "\x00":
            UnicodeString = "\x00{}".format(UnicodeString)
        ASCIIstring = InputString.replace("\x00","")
    else:
        ASCIIstring = InputString
        UnicodeString = "\x00{}".format("\x00".join(InputString))
    
    #ASCII Encoding   
    NoPadASCIIstring = ASCIIstring
    OnePadASCIIstring = "a{}".format(ASCIIstring)
    TwoPadASCIIstring = "aa{}".format(ASCIIstring)
    
    NoPadASCIIB64 = base64.b64encode(NoPadASCIIstring)
    OnePadASCIIB64 = base64.b64encode(OnePadASCIIstring)
    TwoPadASCIIB64 = base64.b64encode(TwoPadASCIIstring)
    
    NoPadASCIIHex = NoPadASCIIB64.encode("hex")
    OnePadASCIIHex = OnePadASCIIB64.encode("hex")
    TwoPadASCIIHex = TwoPadASCIIB64.encode("hex")
    
    NoPadASCIIResults = GetGuaranteedStrings(NoPadASCIIB64,NoPadASCIIstring,NoPadASCIIHex,False)
    OnePadASCIIResults = GetGuaranteedStrings(OnePadASCIIB64,OnePadASCIIstring,OnePadASCIIHex,True)
    TwoPadASCIIResults = GetGuaranteedStrings(TwoPadASCIIB64,TwoPadASCIIstring,TwoPadASCIIHex,True)
    
    #Unicode Encoding
    NoPadUnicodestring = UnicodeString
    OnePadUnicodestring = "a{}".format(UnicodeString)
    TwoPadUnicodestring = "aa{}".format(UnicodeString)
    
    NoPadUnicodeB64 = base64.b64encode(NoPadUnicodestring)
    OnePadUnicodeB64 = base64.b64encode(OnePadUnicodestring)
    TwoPadUnicodeB64 = base64.b64encode(TwoPadUnicodestring)
    
    NoPadUnicodeHex = NoPadUnicodeB64.encode("hex")
    OnePadUnicodeHex = OnePadUnicodeB64.encode("hex")
    TwoPadUnicodeHex = TwoPadUnicodeB64.encode("hex")
    
    NoPadUnicodeResults = GetGuaranteedStrings(NoPadUnicodeB64,NoPadUnicodestring,NoPadUnicodeHex,False)
    OnePadUnicodeResults = GetGuaranteedStrings(OnePadUnicodeB64,OnePadUnicodestring,OnePadUnicodeHex,True)
    TwoPadUnicodeResults = GetGuaranteedStrings(TwoPadUnicodeB64,TwoPadUnicodestring,TwoPadUnicodeHex,True)
    
    #Print it all out ASCII then Unicode
    if VerboseTF:
        print "\n  Base64ced {}:".format(InputString)
        print "   ASCII:"
        print NoPadASCIIResults[1]
        print OnePadASCIIResults[1]
        print TwoPadASCIIResults[1]
        print "\t-Hex ASCII regex ({}):  {}|{}|{}".format(NoPadASCIIstring,NoPadASCIIResults[2],OnePadASCIIResults[2],TwoPadASCIIResults[2])
    print "\t-B64 ASCII regex ({}):  {}|{}|{}".format(NoPadASCIIstring,NoPadASCIIResults[0],OnePadASCIIResults[0],TwoPadASCIIResults[0])
    
    if VerboseTF:
        print "   Unicode:"
        print NoPadUnicodeResults[1]
        print OnePadUnicodeResults[1]
        print TwoPadUnicodeResults[1]
        print "\t-Hex Uni regex ({}):  {}|{}|{}".format(NoPadUnicodestring,NoPadUnicodeResults[2],OnePadUnicodeResults[2],TwoPadUnicodeResults[2])
    print "\t-B64 Uni regex ({}):  {}|{}|{}".format(NoPadUnicodestring,NoPadUnicodeResults[0],OnePadUnicodeResults[0],TwoPadUnicodeResults[0])

def GetGuaranteedStrings(B64Data,ASCIIstring,HexData,PaddedTF):
    if PaddedTF:
        if B64Data[-1] == "=":
            return [B64Data[4:-4] , "\t({})  -  ({}) {} ({})  -  ({}) {} ({}) ".format(ASCIIstring,B64Data[:4],B64Data[4:-4],B64Data[-4:],HexData[:8],HexData[8:-8],HexData[-8:]),HexData[8:-8]]
        else:
            return [B64Data[4:] , "\t({})  -  ({}) {}  -  ({}) {}".format(ASCIIstring,B64Data[:4],B64Data[4:],HexData[:8],HexData[8:]),HexData[8:]]
    
    else:
        if B64Data[-1] == "=":
            return [B64Data[:-4], "\t({})  -  {} ({})  -  {} ({}) ".format(ASCIIstring,B64Data[:-4],B64Data[-4:],HexData[:-8],HexData[-8:]),HexData[:-8]]
        else:
            return [B64Data, "\t({})  -  {}  -  {}".format(ASCIIstring,B64Data,HexData),HexData]
    
def main():
    if "-q" in sys.argv:
        VerboseTF = False
    else:
        VerboseTF = True
        print "\n\t[INFO] - You can run this script in 'QUIET' mode with a -q argument"
    
    #If a file is not used, keep asking for input to Base64ce
    if (len(sys.argv) == 1) or (len(sys.argv) == 2 and not VerboseTF):
        print "\t[INFO] - You can Base64ce strings from a file with 'Base64ce.py <file>'"
        InputString = raw_input("\n\tString to base64ce: ")
        while InputString:
            base64ceString(InputString.replace("\r","").replace("\n",""),VerboseTF)
            InputString = raw_input("\n\tString to base64ce: ")
        
    #if a file is used, Base64ce the lines in it
    else:
        if "-q" in sys.argv[1]:
            stringFile = open(sys.argv[2])
        else:
            stringFile = open(sys.argv[1])
        InputString = stringFile.readline()
        while InputString:
            base64ceString(InputString.replace("\r","").replace("\n",""),VerboseTF)
            InputString = stringFile.readline()
   
if __name__ == "__main__":
    main()
    
