# RealOrNot

Category: `misc`

Points: `333`

Solves: 23

Description:

> Are these pictures real or not?

---

Server code:

```python
import os
import random
import base64
import sys
import signal
import hashlib
import string
from flag import FLAG

sys.stdout = open(sys.stdout.fileno(), mode='w', buffering=1, encoding='utf-8')
sys.stdin = open(sys.stdin.fileno(), mode='r', buffering=1, encoding='utf-8')

def encode_image_to_base64(file_path):
    with open(file_path, 'rb') as image_file:
        encoded_string = base64.b64encode(image_file.read())
    return encoded_string.decode('utf-8')

# Define the signal handler for the alarm
def signal_handler(signum, frame):
    raise Exception("Time is up!")

# Set up the signal to catch SIGALRM and use the handler
signal.signal(signal.SIGALRM, signal_handler)

def generate_pow_challenge(difficulty=4):
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    prefix = "0" * difficulty
    print(f"PoW Challenge: SHA256(solution + '{challenge}') must start with '{prefix}'.")
    return challenge, prefix

def verify_pow_solution(challenge, solution, prefix):
    guess = solution + challenge
    guess_hash = hashlib.sha256(guess.encode()).hexdigest()
    return guess_hash.startswith(prefix)

def play_game():
    # PoW challenge
    challenge, prefix = generate_pow_challenge(difficulty=4)  # Difficulty can be adjusted
    solution = input("Enter PoW solution: ").strip()
    if not verify_pow_solution(challenge, solution, prefix):
        print("Invalid PoW solution. Access denied.")
        return
    else:
        print("PoW solution accepted. Starting the game...")

    try:
        correct_answers = []  # List to store the correct answers
        for _ in range(20):  # 20 rounds of the game
            files = [f for f in os.listdir('folder') if os.path.isfile(os.path.join('folder', f))]
            chosen_file = random.choice(files)
            file_path = os.path.join('folder', chosen_file)
            correct_answer = chosen_file[-1].upper()
            correct_answers.append(correct_answer)  # Store the correct answer
            
            encoded_image = encode_image_to_base64(file_path)
            print(f"Round {_+1}: Is this picture real or not (Y/N)? \n{encoded_image}\n")
        
        # Set an alarm for 10 seconds before input
        signal.alarm(10)
        data = input("Enter your answers for all 20 rounds (Y/N): ").strip().upper()
        signal.alarm(0)  # Cancel the alarm if input is received in time

        if len(data) != 20:
            print("Invalid input. You must enter exactly 20 characters (Y/N). Game over.\n")
            return

        for i in range(20):
            if data[i] != correct_answers[i]:
                print(f"Incorrect answer. Game over.\n")
                return
            
        print(f"Congratulations! You've completed all rounds correctly. Here is your flag: {FLAG}\n")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    play_game()
```

Note that the server for some reason uses a slightly different version. This version matches more similarly with [RealOrNotRevenge](realornotrevenge.md). Notably the key difference is that this challenge provides info on the first round we failed at, while the revenge challenge (hardened) doesn't.

```
Enter your answers for all 20 rounds (Y/N): NNNNNNNNNNNNNNNNNNNN
Incorrect answer for Round 3. Game over.
```

```
Enter your answers for all 20 rounds (Y/N): NNNNNNNNNNNNNNNNNNNN
Incorrect answer. Game over.
```

But first we have to clear the POW. This is pretty straightforward as we can (or rather, we are meant to) just brute the solution:

```python
PREFIX = '0'*4
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
```

---

Now onto the actual challenge. The main gist is that,

1. We are provided 20 random images (full data provided, encoded in b64) drawn from a pool of real and fake images.
2. We are asked to guess whether each of the images is real (Y) or fake (N).
3. If we guess all 20 images correctly, we get the flag. If not, we are told the first round which we guessed incorrectly.

Based on this, it is pretty obvious that we can simply "brute" the images by maintaining a database for which images are real or fake. (In reality we just need a database of real images.) By repeatedly guessing and updating the database, we can eventually guess everything correct.

For example, let's say we start off fresh, and the first 3 images are `AAAA`, `BBBB` and `CCCC`. We send our input and get this result:

```
Enter your answers for all 20 rounds (Y/N): NNNNNNNNNNNNNNNNNNNN
Incorrect answer for Round 3. Game over.
```

We immediately learn that:

1. `AAAA` is fake, otherwise the game would have ended at round 1
2. `BBBB` is fake, otherwise the game would have ended at round 2
3. `CCCC` is real, otherwise the game would **not** have ended at round 3

Here we add `CCCC` to our database, and run the game again.

Let's say the first 2 images are now `CCCC` and `DDDD`.

```
Enter your answers for all 20 rounds (Y/N): YNNNNNNNNNNNNNNNNNNN
Incorrect answer for Round 2. Game over.
```

We input Y for round 1, as the first image is `CCCC` and we already know that it is real. Now we learn that `DDDD` is *also* real, as the game would **not** have ended at round 2 otherwise. We then add `DDDD` to our database.

This process continues until we finally manage to guess everything right.

---

## Solve Script

```python
import hashlib
import string
from subprocess import Popen, PIPE
import time

def verify_pow_solution(challenge, solution, prefix):
    guess = solution + challenge
    guess_hash = hashlib.sha256(guess.encode()).hexdigest()
    return guess_hash.startswith(prefix)

PREFIX = '0'*4
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

# database of real images
Y = set()
def run():
    fw = open('output', 'w')
    p = Popen(
        '[nc -X connect -x [REDACTED]]'.split(),
        stdin=PIPE,
        stdout=fw,
        stderr=fw
    )

    # solve POW
    while True:
        with open('output') as f:
            line = f.read()
        if 'PoW Challenge' in line:
            challenge = line.split("'")[1]
            print(f'Challenge: {challenge}')
            p.stdin.write(solve_pow(challenge, PREFIX).encode() + b'\n')
            p.stdin.flush()
            break

    # retrieve all 20 image data
    cur = []
    while True:
        f = open('output')
        cur = [
            line
            for line in f.read().strip().splitlines()
            if line.startswith('iVBOR')
        ]
        if len(cur) == 20:
            break
        f.close()

    # we provide an "educated" guess.
    # we input Y for images that we were told were real,
    # and N otherwise (can either be fake or unknown).
    res = ''.join(
        'Y' if line in Y else 'N'
        for line in cur
    )
    print(res)
    p.stdin.write(res.encode() + b'\n')
    p.stdin.flush()

    # attempt to read the result of the guess
    time.sleep(0.2)
    tries = 0
    while True:
        res = f.read()
        if 'Incorrect' in res:
            # the guess is incorrect, but that's alright.
            # we have learnt a new image that is necessarily real,
            # so we add it to our real image database.
            idx = int(res.split('for Round ')[1].split('.')[0])-1
            Y.add(cur[idx])
            print(f'Added idx {idx} to database (size: {len(Y)})')
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

while not run():
    pass
```

```
flag{DeepFake_1s_Ea5y_aNd_1ntere5t1ng!}
```

P.S. I hate python subprocess
