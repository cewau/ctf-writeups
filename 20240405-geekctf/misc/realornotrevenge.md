# RealOrNotRevenge

Category: `misc`

Points: `500`

Solves: 12

Description:

> RealOrNotRevenge

---

The server provided is practically identical to the one from [RealOrNot](realornot.md), hence I won't show it here. (Except maybe the POW is slightly harder but that's irrelevant.)

Once again, unlike RealOrNot, this time we do not know which round our answer fails at, which means we won't get to brute the image. With no other "loopholes" in sight, it probably means we are forced to actually parse the images to some extent to determine its realness.

(In some way adapted from [RealOrNot solve script](realornot.md#solve-script))

```python
from base64 import b64decode

with open('output') as f:
    images = [
        line
        for line in f.read().strip().splitlines()
        if line.startswith('/9j/4AA')
    ]

for i, x in enumerate(images):
    with open(f'images/image-{i}.jpeg', 'wb') as f:
        f.write(b64decode(x))
```

But of course, there's probably no way we can reliably (close to 100%) identify AI-generated images from real ones anymore, at least programmatically. And with quite a handful of solves on this challenge, we can reasonably rule this route out.

This means we have to look at some other characteristic of the images to find some pattern. Unfortunately their metadata all look pretty much identical at first glance. However after scanning through the images, we quickly identify an interesting characteristic, that is, there are only a handful of possible image dimensions.

```python
import struct

sizes = []
for i in range(20):
    with open(f'images/image-{i}.jpeg', 'rb') as f:
        sizes.append(struct.unpack('>H', f.read()[0xa3:0xa5])[0])
print(sizes)
print(set(sizes))
```

```
[768, 985, 985, 1024, 1024, 1024, 1024, 768, 1024, 1024, 985, 985, 768, 1024, 704, 985, 985, 1024, 985, 985]
{768, 985, 704, 1024}
```

Taking a wild guess, it could possibly be that images of certain dimensions are real and that of other dimensions are fake. No harm testing this out, right?

Our approach shall be:

1. Maintain a growable database of found image sizes. (In case there are other sizes yet to be found)
2. For each iteration, test a certain combination of real sizes and fake sizes. The easiest way to search exhaustively is to utilise the binary representation of the current iteration number to decide which index is real or fake.
3. If our hypothesis is correct, we will eventually run into the correct combination which will yield us the flag. If not, we will unfortunately have to try some other characteristic. (Spoiler: It worked)

---

## Solve Script

```python
import hashlib
import string
from subprocess import Popen, PIPE
import time
from base64 import b64decode
import struct

def verify_pow_solution(challenge, solution, prefix):
    guess = solution + challenge
    guess_hash = hashlib.sha256(guess.encode()).hexdigest()
    return guess_hash.startswith(prefix)

PREFIX = '0'*5
VALID = [ord(x) for x in string.ascii_letters + string.digits]
BASE = len(VALID)

def solve_pow(challenge, prefix):
    for length in range(10):
        for i in range(BASE**length):
            j = i
            tmp = []
            while j:
                tmp.append(VALID[j % BASE])
                j //= BASE
            solution = bytes(tmp).decode()
            if verify_pow_solution(challenge, solution, prefix):
                return solution

SIZES = []
Y = set()

# change the current list of which image sizes are real
def shuffle(n):
    global Y
    # for each bit in the iteration, if the bit is true,
    # mark the corresponding indexed size in the database as real
    Y = {SIZES[i] for i, x in enumerate(bin(n)[:1:-1]) if int(x)}

# extract the useful information (size) from the image bytestream
def convert(line):
    tmp = struct.unpack('>H', b64decode(line)[0xa3:0xa5])[0]
    # if new size encountered, add to database
    if tmp not in SIZES:
        SIZES.append(tmp)
        print(f'Found {tmp}, now SIZES is {SIZES}')
    return tmp

def run(iteration):
    fw = open('output', 'w')
    p = Popen(
        'nc -X connect -x [REDACTED]'.split(),
        stdin=PIPE,
        stdout=fw,
        stderr=fw
    )

    while True:
        with open('output') as f:
            line = f.read()
        if 'PoW Challenge' in line:
            challenge = line.split("'")[1]
            print(f'Challenge: {challenge}')
            p.stdin.write(solve_pow(challenge, PREFIX).encode() + b'\n')
            p.stdin.flush()
            break

    cur = []
    while True:
        f = open('output')
        cur = [
            line
            for line in f.read().strip().splitlines()
            if line.startswith('/9j/4AA')
        ]
        if len(cur) == 20:
            break
        f.close()
    res = ''.join(
        'Y' if convert(line) in Y else 'N'
        for line in cur
    )
    print(res)
    p.stdin.write(res.encode() + b'\n')
    p.stdin.flush()

    time.sleep(0.2)
    tries = 0
    while True:
        res = f.read()
        if 'Incorrect' in res:
            # if incorrect, try the next combination of real and fake sizes
            shuffle(iteration)
            print('Changing to', Y)
        elif 'Congratulations' in res:
            print(res)
            f.close()
            return True
        elif tries < 5:
            tries += 1
            print('Not yet, trying again...')
            time.sleep(1)
            continue
        break
    
    p.kill()
    fw.close()
    f.close()
    print()
    return False

iteration = 0
while not run(iteration:=iteration+1):
    pass
```

```
Challenge: 7htDmHbdmFfSZlaK
Found 832, now SIZES is [832]
Found 985, now SIZES is [832, 985]
Found 1024, now SIZES is [832, 985, 1024]
Found 768, now SIZES is [832, 985, 1024, 768]
Found 896, now SIZES is [832, 985, 1024, 768, 896]
NNNNNNNNNNNNNNNNNNNN
Changing to {832}

Challenge: jrtBHDcMsiBnF3Yc
NNNNNNNNYNNNNNNNNNNN
Changing to {985}

Challenge: smUhfOAdYq3i50Lx
NYYNYYYYYYNYNYYNYNYY
Changing to {832, 985}

Challenge: Rh34mMFCVo6wA5sF
YNYYNNNNYYYNYNNYNNYY
Changing to {1024}

Challenge: yAfPL8GStixcPPOW
Found 704, now SIZES is [832, 985, 1024, 768, 896, 704]
YYNNNNNYYNNNNNNNNNNY
Congratulations! You've completed all rounds correctly. Here is your flag: flag{Revenge_1s_Ea5y_aNd_1ntere5t1ng!}
```
