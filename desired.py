number = 7
p = 1
mult = 0
counter = 0
while 1:
    mult = p*number
    
    if (str(mult)).count('7') != 0:
        counter += 1
        print(str(counter) + ": " + str(mult))
        
    if counter == 48:
        print(mult)
        break
    p += 1
