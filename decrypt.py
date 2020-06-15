import hashlib
import os

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

for y in range(1, 12):
    for i in range(1, 31):
        x = "2020-" + "{:02d}".format(y) + "-" + "{:02d}".format(i) + " raccoon"
        print(x)
        sha_signature = encrypt_string(x)
        cmd1 = 'echo ' + sha_signature + ' | gpg --batch --yes --passphrase-fd 0 /home/msi/Desktop/sekritbackups2444/firefox.log.gz.gpg'
        cmd2 = 'echo ' + sha_signature + ' | gpg --batch --yes --passphrase-fd 0 /home/msi/Desktop/sekritbackups2444/signal.log.gpg'
        print(cmd1)
        os.system(cmd1)
        os.system(cmd2)
