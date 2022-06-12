# equation

> Looking at equation gives me headache
> 
> MD5 (equation.zip) = 2736761ba7d878b1a50aa2cc1814fcd5
> 
> - mechfrog88

Let us look at `main.py`:

```python
from Crypto.Util.number import bytes_to_long

FLAG = <REDACTED>

n = len(FLAG)
m1 = bytes_to_long(FLAG[:n//2])
m2 = bytes_to_long(FLAG[n//2:])

print(13 * m2 ** 2 + m1 * m2 + 5 * m1 ** 7)
print(7 * m2 ** 3 + m1 ** 5)
```

### note:

* The outputs of the 2 _equations_ can be found right below the script, commented out (omitted here for tidyness)

* For simplicity sake, I will refer to the 2 variables (`m1` and `m2`) as `x` and `y` respectively

Being relatively inexperienced at crypto (and the myriad of wonderful "tools" that definitely do not spit the answer out immediately allowing for a 5-minute solve), I used neither Mathematica (didn't know it exists) nor Z3 (thought the numbers were too big to bother trying), unlike probably everyone else who solved this challenge.

Instead, I capitalised on a fatal weakness in the "encryption":

$$
\begin{aligned}
a &= 13y^2+xy+5x^7 \\
0 &= y^2+2\left(\frac{x}{26}\right)y+\frac{5x^7-a}{13} \\
y &= -\frac{x}{26}\pm\sqrt{\left(\frac{x}{26}\right)^2-\frac{5x^7-a}{13}}
\end{aligned}
$$

That's right, the first equation is a **quadratic equation** in terms of `y`. Note that the negative root can be immediately rejected as `x` and `y` are both positive.

Plugging this into the second equation:

$$
\begin{aligned}
b &= 7y^3+x^5 \\
&= 7\left(-\frac{x}{26}+\sqrt{\left(\frac{x}{26}\right)^2-\frac{5x^7-a}{13}}\right)^3+x^5 \\
\end{aligned}
$$

Unfortunately, we still cannot plug this into sage directly for some reason (it just spits out the original equation).

However, plugging this into desmos instead shows us that for large enough values of $a$ (basically negligible compared to the 100+ digit numbers provided), the graph of $b$ against $x$ is strictly decreasing (EXCEPT for an extremely tiny interval near the right end of the interval of all possible values of $x$ -- we can probably just pretend it doesn't exist).

This means that we can simply solve for $x$ digit by digit:

```python
# sage
a = 6561821624691895712873377320063570390939946639950635657527777521426768466359662578427758969698096016398495828220393137128357364447572051249538433588995498109880402036738005670285022506692856341252251274655224436746803335217986355992318039808507702082316654369455481303417210113572142828110728548334885189082445291316883426955606971188107523623884530298462454231862166009036435034774889739219596825015869438262395817426235839741851623674273735589636463917543863676226839118150365571855933
b = 168725889275386139859700168943249101327257707329805276301218500736697949839905039567802183739628415354469703740912207864678244970740311284556651190183619972501596417428866492657881943832362353527907371181900970981198570814739390259973631366272137756472209930619950549930165174231791691947733834860756308354192163106517240627845889335379340460495043

f(x) = 7*(x/(-26) + pow((x/26)**2 - (5*x**7-a)/13, 0.5))**3 + x**5

sx = 0
while True:
    cur = f(10**sx)
    if cur not in RR or cur - b < 0:
        break
    sx += 1
sx -= 1
print(sx)
```

The output is `69`, which means that $10^{69} < x < 10^{70}$.

```python
# sage
val = 0
for exp in range(sx, -1, -1):
    for digit in range(1, 10):
        cur = f(val + digit*10**exp)
        if cur not in RR or cur - b < 0:
            val += (digit-1)*10**exp
            break
        if digit == 9:
            val += 9*10**exp

assert f(val) - b == 0
print(val)
```

```
2788921852171221111440879057471155338995686075935079372721930964530280
```

And we have found `x`! From here, we can simply solve the second equation to retrieve `y`.

```python
# sage
assert (b-val**5) % 7 == 0
print(pow((b-val**5)//7, 1/3))
```

```
672606797059492205907266474240230882559524138683883170067899497957191549
```

And that's it! If we convert the numbers back to text, we get the flag:

```python
from Crypto.Util.number import long_to_bytes

m1 = 2788921852171221111440879057471155338995686075935079372721930964530280
m2 = 672606797059492205907266474240230882559524138683883170067899497957191549

print((long_to_bytes(m1) + long_to_bytes(m2)).decode())
```

`grey{solving_equation_aint_that_hard_rite_gum0pX6XzA5PJuro}`
