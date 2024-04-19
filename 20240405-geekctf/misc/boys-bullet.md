# Boy's Bullet

Category: `misc`

Points: `250`

Solves: 34

Description:

> It was the spring of 2024 when a boy born in millennium picked up a real gun on the road. Because he was young, ignorant and fearless, he pulled the trigger. No one died and no one was injured. He thought he had fired a blank shot. Fourteen years later, he heard a faint sound of wind behind him while walking on the road. He stopped and turned around. The bullet hit him between the eyebrows.
> 
> curl http://chall.geekctf.geekcon.top:10038

---

Interesting concept for a challenge.

```bash
$ curl http://chall.geekctf.geekcon.top:10038
Please upload a photo to receive the boy's bullet
    command: curl -T <filename> http://<ip>:<port>
```

As someone [capable of following instructions](#appendix), I proceeded to upload a (random) image to the server:

```bash
$ curl -T qrcode2.png http://chall.geekctf.geekcon.top:10038
Photo must be in JPEG format
```

Okay, sure. I then uploaded a (random) JPEG image to the server:

```bash
$ curl -T solve.jpeg http://chall.geekctf.geekcon.top:10038
The photo contains no timestamp, I don't know how long it will take you to receive this bullet
```

We know that JPEG is capable of storing a wide range of metadata, the timestamp of the image being one of them. Somehow I tried a whole bunch of random images online and they all didn't work; the most straightforward method I took is to find an image taken by a really high quality camera or something -- that usually contains a whole lot of metadata.

```bash
$ curl -T solve.jpeg http://chall.geekctf.geekcon.top:10038
The photo is from 2008, you are still not old enough to receive the boy's bullet
```

From the description we can deduce that we are to receive the boy's bullet in 2038. With EXIF, it is as simple as opening a random hex editor and literally modifying the timestamp stored within it (it is not encoded in some funny way).

```bash
$ hexdump -C solve.jpeg | head -n 20
00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 01 00 48  |......JFIF.....H|
00000010  00 48 00 00 ff e1 09 ac  45 78 69 66 00 00 49 49  |.H......Exif..II|
00000020  2a 00 08 00 00 00 0b 00  0f 01 02 00 06 00 00 00  |*...............|
00000030  92 00 00 00 10 01 02 00  0e 00 00 00 98 00 00 00  |................|
00000040  12 01 03 00 01 00 00 00  01 00 00 00 1a 01 05 00  |................|
00000050  01 00 00 00 a6 00 00 00  1b 01 05 00 01 00 00 00  |................|
00000060  ae 00 00 00 28 01 03 00  01 00 00 00 02 00 00 00  |....(...........|
00000070  31 01 02 00 0b 00 00 00  b6 00 00 00 32 01 02 00  |1...........2...|
00000080  14 00 00 00 c2 00 00 00  13 02 03 00 01 00 00 00  |................|
00000090  02 00 00 00 69 87 04 00  01 00 00 00 d6 00 00 00  |....i...........|
000000a0  25 88 04 00 01 00 00 00  d2 03 00 00 e4 03 00 00  |%...............|
000000b0  43 61 6e 6f 6e 00 43 61  6e 6f 6e 20 45 4f 53 20  |Canon.Canon EOS |
000000c0  34 30 44 00 48 00 00 00  01 00 00 00 48 00 00 00  |40D.H.......H...|
000000d0  01 00 00 00 47 49 4d 50  20 32 2e 34 2e 35 00 00  |....GIMP 2.4.5..|
000000e0  32 30 33 38 3a 30 37 3a  33 31 20 31 30 3a 33 38  |2038:07:31 10:38|
000000f0  3a 31 31 00 1e 00 9a 82  05 00 01 00 00 00 44 02  |:11...........D.|
00000100  00 00 9d 82 05 00 01 00  00 00 4c 02 00 00 22 88  |..........L...".|
00000110  03 00 01 00 00 00 01 00  00 00 27 88 03 00 01 00  |..........'.....|
00000120  00 00 64 00 00 00 00 90  07 00 04 00 00 00 30 32  |..d...........02|
00000130  32 31 03 90 02 00 14 00  00 00 54 02 00 00 04 90  |21........T.....|
```

```bash
$ curl -T solve.jpeg http://chall.geekctf.geekcon.top:10038
flag{47_7h15_m0m3n7_3duc4710n_h45_c0mp1373d_4_72u1y_c1053d_100p}
```

---

## Appendix

While I was writing the writeup for this challenge I decided to mess with the server a bit.

```bash
$ cp qrcode2.png qrcode2.jpeg; curl -T qrcode2.jpeg http://chall.geekctf.geekcon.top:10038 > out.html
```

We actually get a pretty interesting [exception traceback](../files/boys-bullet.html) just like that!

Notably, we get a snippet of the server code:

```python
File "/boys-bullet/server.py", line 15, in upload
 
@app.route("/<filename>", methods=["PUT"])
def upload(filename):
    if not filename.endswith("jpeg"):
        return "Photo must be in JPEG format\n"
    image = Image(request.data)
    try:
        # fetch timestamp from exif data
        exif_time = datetime.fromisoformat(image["datetime"].replace(":", "-", 2))
        exif_timestamp = c_int(int(exif_time.timestamp()))
        # fetch current timestamp
```

Here we can see which field was actually used for the timestamp stage, which would have reduced some of the headaches while attempting this challenge.
