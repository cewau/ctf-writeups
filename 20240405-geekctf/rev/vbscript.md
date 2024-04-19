# VBScript

Category: `rev`

Points: `611`

Solves: 8

Description:

> \*flag format: flag{.\*}

---

This challenge simply has a flag checker obfuscated inside the VBScript code through the use of `execute` (which does what you expect it to do).

The immediate approach is to craft a wrapper around `execute` to display each snippet before it is executed. But unfortunately I have a skill issue (mainly scoping problems) and I was unable to automate the process. So instead I decided to deciper it manually until I reach the part where it gets repetitive and automatable (definitely necessary given the size of this challenge).

```vbscript
sub execute(x):
    wscript.echo x
    wscript.quit
end sub
```

For starters, not all the code is at the bottom of the script. There is also an obfuscated portion scattered throughout the long variable definitions.

```python
import re

with open('problem.vbs') as f:
    RAW = f.read().strip().splitlines()

with open('out.vbs', 'w') as f:
    for line in RAW:
        tmp = re.sub(r'.{4}=".*?"', '', line)
        f.write(tmp + '\n' if tmp else '')
```

```vbscript
:Dim pzbJ, qQyc, KjHf
:Set pzbJ = CreateObject("Scripting.FileSystemObject")
:Dim KgMQ
:KgMQ = WScript.ScriptFullName
:Set qQyc = pzbJ.OpenTextFile(KgMQ, 1)
:KjHf = qQyc.ReadAll
:qQyc.Close
:Dim WqPU
:WqPU = Split(KjHf, vbCrLf)
:Dim UDEP
:For Each rRhG In WqPU:Dim PmfF:PmfF = InStrRev(rRhG, chr(39)):If PmfF > 0 Then:Dim commentLfMQ:commentLfMQ = Trim(Mid(rRhG, PmfF + 1)):If Len(commentLfMQ) > 0 Then:UDEP = UDEP & commentLfMQ:End If:End If:Next
:
:QFdO=15
:do while len(UDEP)>1:iWuR=iWuR&eval("chr(&h"+left(UDEP,2)+"xor "+cstr(QFdO)+")"):UDEP=mid(UDEP,3):loop
:wscript.echo iWuR
'4C5A4245322D695F4758
'2D35697A616C7B666061
'2F43477A772746485A78
' ...
'3C3B3A39383736242032
'2D
```


But that wasn't an issue as whatever we want to see also gets captured by the `execute` "breakpoint":

```vbscript
CUMJ="fPHW":function LHux(IGUw):x="657865637574652022666F722069693D3120746F206C656E2849475577292226766263726C66262274743D617363286D696428494755772C69692C3129292226766263726C662622666F72206A6A3D3020746F2075626F756E642866576545295C332226766263726C6626226966202874743E3D66576545286A6A2A332B30292B66576545286A6A2A332B3229616E642074743C3D66576545286A6A2A332B31292B66576545286A6A2A332B322929207468656E2226766263726C66262274743D74742D66576545286A6A2A332B32292226766263726C6626226578697420666F722226766263726C662622656E642069662226766263726C6626226E6578742226766263726C6626224C4875783D4C4875782B636872287474292226766263726C6626226E65787422":y="execute """"":z="&chr(&h":w=")"
' for ii=1 to len(IGUw)
' tt=asc(mid(IGUw,ii,1))
' for jj=0 to ubound(fWeE)\3
' if (tt>=fWeE(jj*3+0)+fWeE(jj*3+2)and tt<=fWeE(jj*3+1)+fWeE(jj*3+2)) then
' tt=tt-fWeE(jj*3+2)
' exit for
' end if
' next
' LHux=LHux+chr(tt)
' next
end function
function base64Decode(inputString)
  Dim dataLength, sOut, groupBegin
  Const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
'   ...
end function
BfGI = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
```

`LHux`, as we will see later, is a frequently used deobfuscator function where it uses an array (`fWeE`) to shift bytes within each specified range by a set amount.

With that out of the way, let us take a look at our "`main`":

```vbscript
jcHl = mPXF
execute base64Decode(jcHl)
```

```vbscript
kUiA="p2B=)*<)S%=)	>()=#&&HS<={*?&	;%&S%ywp	B	>u<*;';*&%&S;B	>u<*;y1H&SZwp)><*()=)&HS<<*%&&%N&=)&;&?*?&<":OKjp="fWeE=ArRaY(40,49,-26,50,57,-18)":NayO="p0&%S<p=@	>%#>;0	&uS%)*<*Y>;Bwp)&(S	&;=	)*<H*=B]Z&&p%#&'	;&)*wpp@S<?&;B'S*=B)&<S*%p0*<&p%*<*<<p%&":svHC="AY$;,&?Sqo)t]1)vr":qeHe="p1	&<*<%	#&S;=)&*;H;*?*&(&	&S;=)uwp{%<	%	=)B	>;<B	>;'S>=@S<	=B	>;'	Bwp&&%<><=B	>SBB	>;)&S;=S=)*<%*<H	<&uwp1>#Y&$=&%=;*#>=&=	$	S%*(	?&uwp{(S*<=@)	<&'>;BS%>S=$)&%'	;$&":ext=":execute(LHux(":mNvL="p.0\1](		%=*&5A*=.0\1wp4[v5)&)S%=)S=)S=)S%&B	>'S*;)S=)S%&B	>(		%=)&wp(		%&<<=)S=*<$)&SH*#&S>=BSZ&<#&S>=B#;*&'*(		%&<<":JgHO="3(4>,S;;SBq<xZu5=C;uxB/u)H1u]6Zu@.Auv>&u$N%u/3uC3=u%?Bu\&%u[@2;u]Au.M0u<=Hrnw01CH,01CHtnw&A&$>=&&A&$>=&(M&$qt3(4>qAY$;q*%q><S>u01CHurrrtr":vSln="pI{[35I]#&<&&$)B	>u<*;u(	BB	>(S<=&;%	=)&AH&$=B	>;wp;&H;	S$)wp1NI3v1	%	])*<":jxSG="fWeE=aRRay! !%&''&#$!%""%""#!''!!&#&$$#'#'""&$%%#!##%%$%%!'' # $$'  ""$$%$$!$##&!&""""%!%#%#""!$$ %%&%'##' ' !%&&!!""'""'%""%%""'!!'%&""&""% #$#%!'!'!'&&&'!!""!""## &% % #"" ""##& &%&%$#&#&!&%!%! ":fut=":function ":eft=")):end function":jUAq="p45145J{p*<&&=]<)	>%#&><&%<	u?&;B&&=wp	@)S?&]#&&#&)S?&%u=)S=)&*()=<=*$Zwp)&<Sp<=	H**		B&S<=*<><&y":nxdL="p1)&<=;*Z&>H	=)&#&x&==)&&=	#&%5A*=1&;?S=wp]<=)*<S%S((&;@)*$)]<&&#&'	;&&uwp)&)S%&=	@S;%B)S%y3	&u&=&$>=$)=)&&":Matx="2'x],1v*;C#}$%!""{~MA(<N	J6=3tx2GO/ZF?@&]0[\4.|IB>YS'H)5 ,nwY$,&]nw(M&$,#S<&}""4&$	%&qr":aft=")):end function:function ":GqYP="p5=&;.]1{]wp3I5p*<(S;&=<p	@=)&%&?*wp]Jx5	4	;	=)BB@	S)*&=)&&H;&<&=B":kBsg="p{)S=&;u<	%*&;<S()*	=)*<=;&&uwp{%#B)*<<*%&)*<';>*=	'#S<=S;%Bwp{{0	>$)	==)&#	Bu)&*<	';	BS#		%":execute OKjp
execute (ext&"jxSG))"&ext&"JgHO))"&fut&"gXec(lHeI)"&ext&"Matx"&aft&"xjcr(IShK)"&ext&"svHC"&aft&"RDOW()"&ext&"jUAq"&aft&"MExO()"&ext&"qeHe"&aft&"Jxrg()"&ext&"kBsg"&aft&"gGmy()"&ext&"kUiA"&aft&"cRSp()"&ext&"nxdL"&aft&"XnNh()"&ext&"NayO"&aft&"Kwvt()"&ext&"GqYP"&aft&"IhgY()"&ext&"vSln"&aft&"rCNR()"&ext&"mNvL"&eft)
```

```vbscript
' execute OKjp
fWeE=ArRaY(40,49,-26,50,57,-18)
```

```vbscript
' execute (ext&"jxSG))"&ext&"JgHO))"...
:execute(LHux(jxSG)):execute(LHux(JgHO)):function gXec(lHeI):execute(LHux(Matx)):end function:function xjcr(IShK):execute(LHux(svHC)):end function:function RDOW():execute(LHux(jUAq)):end function:function MExO():execute(LHux(qeHe)):end function:function Jxrg():execute(LHux(kBsg)):end function:function gGmy():execute(LHux(kUiA)):end function:function cRSp():execute(LHux(nxdL)):end function:function XnNh():execute(LHux(NayO)):end function:function Kwvt():execute(LHux(GqYP)):end function:function IhgY():execute(LHux(vSln)):end function:function rCNR():execute(LHux(mNvL)):end function
```

```vbscript
' execute(LHux(jxSG))
fWeE=aRRay(32,37,-18,10,10,109,98,105,-63,74,74,-53,91,91,-33,85,86,6,59,59,-48,106,107,-17,53,55,71,76,77,-3,90,90,-11,125,126,-69,112,112,-40,66,70,-16,63,65,58,38,44,73,75,75,43,60,62,-17,78,79,-55,92,92,-37,80,83,-34,94,97,-14,71,71,49,13,13,97,84,84,-72,56,57,-31,93,93,-91,88,89,-11,113,113,-43,45,52,-18,72,72,-50,114,124,-55,108,111,-102,87,87,-16,58,58,-38,73,73,20)
```

```vbscript
' execute(LHux(JgHO))
CgDu=array("sGOk","Etzr","lGyQ","hpnS","IFlk","nwPx","Kume","cYOd","mQCO","zmCt","Hdvy","VeJd","UwBr","IxNN","PNXR","sJtp")
RSzp=RSzp+1
execute "execute gXec("+CgDu(xjcr(mid(usau, RSzp, 1)))+")"
```

```vbscript
' function xjcr(IShK):execute(LHux(svHC)):end function
xjcr = eval("&h0"+IShK)
```

We pause for a moment here. We see that our input (`usau`) is currently being enumerated, which is a very good sign. Note that our input is currently converted into a hexstring, as shown here:

```vbscript
' input = flag{aaaabbbbccccddddeeeeffffgggghhhhiiii}
execute usau
```

```
666C61677B6161616162626262636363636464646465656565666666666767676768686868696969697D
```

Either way, each nibble in the hexstring is accessed on its own and treated as the index to the array in `CgDu`.

```vbscript
' execute "execute gXec("+CgDu(xjcr(mid(usau, RSzp, 1)))+")"
execute gXec(Kume)
```

```vbscript
' function gXec(lHeI):execute(LHux(Matx)):end function
BfGI="SKirzb96cd34A17XxgsYoMFmt/C+GBWlZQkn0HqOvweIRUNVDP5LTyujafpJ8hE2="
jcHl=lHeI
gXec=base64Decode("")
```

... and we are back to `BfGI` and `jcHl`. Looking at the base64Decode code, `BfGI` is the letter set used in the base64 encoding, while `jcHl` is the actual base64 input.

We have finally accessed one of the predefined obfuscated variables. We use the new letter set to decode `Kume`, and we get:

```vbscript
aft=")):end function:function ":fut=":function ":eft=")):end function":jxSG="fWeE=ArraY%&"" # $""! ! '!&%$%!&!&!&&#&$&%%%%'%&""""!#""%$###!%'%'!#!! !$""%$' !&# #! "" ""&&%&%&!&""&"""" ""'""'&""%""% !#!#!""!!!"" $'&""&""&""&& #""""$%&$$#":fnkc="s}}}}P2}32I}sR.uz}C 33C}.v2sJ}v}3v} vz5s}}}}sX3} 2}2}1}3.}.u}2}.1}}uC5s}}}}~.}31}3}/.231v}.}}2uCC}vCs2})|s}}":KldQ="_v.L11)t< _Y<z<T2U<z</S<z<u[a<z<V(!<z<2^R<z<12WY<z<A,<z<v3<z<2B2<z<RvY1<z<V<z<3' 2<z< <z<*X~R<z<u'X<w""5a*/La*/y9""5(3}<(3}V^t<y_v.tV'_,tu t2z}a*/z}9wwwy<w<":ext=":execute(LHux(":eHvD="s}}}}[3}v}10 3} 3}' 3}3}21/v3s2}12;}}5s}}}}U.1} }2}}v.3}.v23z}23z}v}31z5s}}}}~1s2}v.}uv}//)J}3}/123}.}3 1}' 25s}}}}X2}.C}2}2Cv1|5s}},~WT[[,|}}}}}}}}}}}}}}Q }1}.u} 31J}.|}}}}}}}}}T( 3}Tu C |":Levr="s}}}}CC}C2} 2}3..3}.v}1)} vv.v3|5s}}}},}u)}/..1}B v.uz}2 B}' 3}  C}C.'2;5s}}}}v}33}u)}1}.C}v.3}' 3.C}3)}1 .32z":QzkY="s}}~1}3.2}2/1 v2}3.})CC.'}3uv}31vz5s}}Xv}/1.22}.}3}22.v2}}X}2vz5s}}~1}P/1 C}/1u2} v}31}.3}Yv2}1vz5s}} v} 123}X}2'}).}12}' })3}1}1v|":lnqo="QVXL<*YA?!F`~W30P,1Eu()H_y9] RavT&#2BVZ4S%X'@C.U[QD/^GL<""5!WCLA3S""5V^L2E?S.t<<w":dvna="s}}}}3s2}1N}}a2}}sX}z}/.v}2/ C}2z5s}}}}D.s}' 3}.u/22 .v}.}u)}.v31)s2}'1Bz5s}}}}~.31}' 3}3}/ 3 C}.u/C v325s}}}},}2}2}).1}.//122 .v}2}/.vz":OKjp="fWeE=Array(40,49,-26,50,57,-18)":YRgz="s}}DPaVPaT~|}X}u}v'.13)}3.}}Wv1)s2}' |5s}}]UU,[Z|}A.z}v3C}uuJ}X}v'.13)}u5s}}}}~.}'..}2.} 1}}u}3.}} 2}' 5s}}}}Pv}}v.}/.13 .v} v}3}. }u)2C|":nzlx="V'_,}L}Ct<r4<y!Ww":execute OKjp
execute (ext&"jxSG))"&ext&"KldQ))"&fut&"GuYV(NhtD)"&ext&"lnqo"&aft&"GwPO(jHae)"&ext&"nzlx"&aft&"MBmP()"&ext&"fnkc"&aft&"DgAF()"&ext&"YRgz"&aft&"YJrk()"&ext&"QzkY"&aft&"kyYQ()"&ext&"eHvD"&aft&"ImCq()"&ext&"Levr"&aft&"GqGA()"&ext&"dvna"&eft)
```

Notice the similarity? We can verify that the execution flow eventually reaches something very similar to the input and array indexing:

```vbscript
' execute(LHux(KldQ))
vPno=array("iPJW","EsSF","pdDc","mLRY","GXxj","shVC","rsHJ","NfOh","nbbt","sYks","CnJr","WGve","twis","iWWg","zITC","mwdI")
RSzp=RSzp+1
execute "execute GuYV("+vPno(GwPO(mid(usau, RSzp, 1)))+")"
```

We can prod around a bit more with the input if we want, but we can deduce that the flag checker is simply a maze where the correct input leads us to the correct final destination. This reasoning also justifies the 1000+ obfuscated variables in the script.

Side note: One of the "wrong" paths (`sGOk`) looks like this:

```vbscript
' ... long list of variables
:fWeE=ArrAY(40,49,-26,50,57,-18)
:fWeE=array(120,120,-19,36,59,-6,83,84,-27,119,119,-36,34,35,-33,72,74,8,82,82,-68,10,10,55,75,78,-69,99,100,-88,90,90,-5,115,115,-9,101,113,-14,85,89,-70,96,98,11,122,124,-62,79,81,-56,68,71,-42,116,118,-96,60,67,11,121,121,-42,114,114,-14,125,126,-121,95,95,-92,13,13,46,32,33,31,94,94,16,93,93,-35,91,92,-37)
dim bDEe
zOBc()
pmsf()
:function hsqd():hsqd="taskkill /f /im ":end function
:function NiIX():NiIX="wscript.exe":end function
:function IXgS():IXgS="cscript.exe":end function
:function zOBc():set bDEe = Createobject("Wscript.shell"):end function
:function pmsf():bDEe.run hsqd() + NiIX(), 0
bDEe.run hsqd() + IXgS(), 0:end function
:function VpXO():execute(LHux(hTrb)):end function
:function NxQp():execute(LHux(iCeF)):end function
:function CyAB():execute(LHux(rSvR)):end function
:function DmNX():execute(LHux(jfkD)):end function
:function pbUv():execute(LHux(AAyc)):end function
:function KfEN():execute(LHux(ymjs)):end function
:function DbxA():execute(LHux(BAsO)):end function
```

And one of the "unused" functions (`VpXO`) looks like this:

```vbscript
' execute(LHux(hTrb))

'  JULIA. O me unhappy!                                  [Swoons]
'  PROTEUS. Look to the boy.
'  VALENTINE. Why, boy! why, wag! how now!
'    What's the matter? Look up; speak.
'  JULIA. O good sir, my master charg'd me to deliver a ring to Madam  
```

Basically just random junk.

---

## Part II

Now we are ready to automate the checker. We can crack open multiple of the "correct paths" and notice that they all generally follow a similar pattern:

```vbscript
execute(LHux(jxSG))
execute(LHux(JgHO))
function gXec(lHeI)
    execute(LHux(Matx))
end function
function xjcr(IShK)
    execute(LHux(svHC))
end function
```

```vbscript
execute (ext&"jxSG))"&ext&"JgHO))"&fut&"gXec(lHeI)"&ext&"Matx"&aft&"xjcr(IShK)"&ext&"svHC"&aft
```

We can then manually lookup the variables from the big chunk of definitions and crack them open by ourselves to get the next array of "paths" to take.

First we parse the defined variables:

```python
import string
VALID = set(string.ascii_letters.encode())

# pretty rudimentary search-and-parse function
def extract(raw):
    d = {}
    cur = 0
    while True:
        nxt = raw.find(b'"', cur)
        if nxt == -1:
            break
        key = raw[cur:nxt]
        if key[0] == ord(':'):
            key = key[1:]
        if key[-1] == ord('='):
            key = key[:-1]
        assert all(x in VALID for x in key)
        cur = nxt+1
        saved = cur
        while True:
            nxt1 = raw.find(b'"', cur)
            nxt2 = raw.find(b'""', cur)
            if nxt1 != nxt2:
                assert nxt1 != -1
                d[key.decode()] = raw[saved:nxt1].replace(b'""', b'"')
                cur = nxt1+1
                break
            cur = nxt2+2
    return d
```

```python
from base64 import b64decode
mPXF = 'DQprVWlBPSJwDg4ODg4yQg49KSo8DilTJQ49KQk ...'
variables = extract(b64decode(mPXF).splitlines()[1])
print(variables)
```

```
{
    'kUiA': b"p\x0e\x0e\x0e\x0e\x0e2B\x0e ...",
    'OKjp': b'fWeE=ArRaY(40,49,-26,50,57,-18)',
    'NayO': b"p\x0e\x0e\x0e\x0e0&%\x0eS<\x0ep ...",
    'svHC': b'AY$;\x0e,\x0e&?S\x06q\x10o)\x1e\x10t]1)vr',
    ...
}
```

Then we extract out the key variables that get us to the array:

```python
import re

def extract2(raw):
    query = r'execute \(ext&\"jxSG\)\)\"&ext&\"(\w+?)\)\)\"&fut&\"\w+?\(\w+?\)\"&ext&\"(\w+?)\"'
    m = re.match(query, raw)
    return m.group(1), m.group(2)
```

```python
branches, b64key = extract2(b64decode(mPXF).splitlines()[2].decode())
print(branches)
print(b64key)
```

```
JgHO
Matx
```

The first result contains information about the path variables for the next iteration, while the second result contains the letter set for their base64 decoding. But to get there we have to unscramble them (with our own `LHux` function):

```python
ARR = [40,49,-26,50,57,-18]
def unscramble(raw, key=ARR):
    assert len(key)%3 == 0
    res = []
    for i in raw:
        for j in range(len(key)//3):
            s, e, d = tuple(key[j*3:(j+1)*3])
            if s+d <= i <= e+d:
                res.append(i-d)
                break
        else:
            res.append(i)
    return bytes(res).decode()

def solve(variables, branches, b64key):
    key = list(map(int, unscramble(variables['jxSG'])[11:-1].split(',')))
    res1 = unscramble(variables[branches], key)
    res2 = unscramble(variables[b64key], key)
    return (
        [x[1:-1] for x in res1.split('array(')[1].split(')')[0].split(',')],
        res2.split('="')[1].split('"')[0]
    )
```

```python
b, bk = solve(variables, branches, b64key)
print(b)
print(bk)
```

```
['sGOk', 'Etzr', 'lGyQ', 'hpnS', 'IFlk', 'nwPx', 'Kume', 'cYOd', 'mQCO', 'zmCt', 'Hdvy', 'VeJd', 'UwBr', 'IxNN', 'PNXR', 'sJtp']
SKirzb96cd34A17XxgsYoMFmt/C+GBWlZQkn0HqOvweIRUNVDP5LTyujafpJ8hE2
```

And finally to complete the cycle, we simply have to extract out the information from the path variable.

```python
with open('problem.vbs') as f:
    VARS = {
        line[:4]: line[6:line.index('"', 6)]
        for line in f.read().strip().splitlines()
        if line[4:6] == '="'
    }

B64BASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
def get(branch, b64key):
    trans = str.maketrans(b64key, B64BASE)
    res = b64decode(VARS[branch].translate(trans)).split(b'\r\n')
    return res[1], res[2].decode()
```

```python
l1, l2 = get(b[6], bk)
print(l1[:30])
print(l2[:30])
```

```
b'aft=")):end function:function '
execute (ext&"jxSG))"&ext&"Kld
```

With these, we can piece everything together to get the flag.

```python
xx, yy = ['mPXF'], B64BASE
idxs = []
while True:
    candidates = []
    for i, xc in enumerate(xx):
        l1, l2 = get(xc, yy)
        try:
            # we found that only the correct path
            # has l2 in the right format;
            # all other other paths are "dead ends",
            # which means we can just short circuit
            branches, b64key = extract2(l2)
        except:
            continue
        variables = extract(l1)
        candidates.append((i, xc, variables, branches, b64key))
    if len(candidates) == 0:
        # we reached the end
        break
    assert len(candidates) == 1
    i, xc, v, b, bk = candidates[0]
    idxs.append(hex(i)[2])
    xx, yy = solve(v, b, bk)

flag = bytes.fromhex(''.join(idxs[1:]) + 'd').decode()
print(flag)
```

```
flag{d34936b2-3290-4f87-97ab-c02c6688ccc1}
```
