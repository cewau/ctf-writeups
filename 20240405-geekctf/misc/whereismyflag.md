# WhereIsMyFlag

Category: `misc`

Points: `104`

Solves: 95

Description:

> https://github.com/awesome-ctf/2024-WhereIsMyFlag
> 
> (Anything other than this repository is NOT relevant to this task.)

---

Pretty straightforward challenge. When we look at the GitHub repo we are greeted with a pretty innocent-looking python script. On first glance there is nothing wrong with it, but we quick notice that the horizontal scroll bar is uncannily long for a script that did not seem to exceed like 120 lines.

Scrolling horizontally to the end of the script we immediately notice something suspicious:

```python
import gzip; import base64; gzip.decompress(base64.b64decode('H4sIAAAAAAACA5Pv5mAAASbmt3cNuf9EzT3+sN5nQrdr2jIOrcbXJmHROjnJAouEuzN5jcq4Fbf6bN1wVlfNYInA9KvHri/k2HjhUVbxzHOHlB5vNdhWdDOpzPyo0Yy7S+6LFzyoXBVc/0r/+ffe+TVfEr8u/dF93/3if9td8//+Ff//8WK4HQMUNL7+V9J/3fBA+2Ojea/lmaCiC7PLMzf1Mt3zjTvJCBU6+Pp00v6/Ah92xQpbQoUUKm7azN2meyBZkk/cFi52vlpmbXQD0LhshLq3er7XdB2+533y4oOKccTFi/1+63HgdZnvE6hQw4PUzyW3tjH0p1rEfIGL2b4v3JLH2He6Yt1TuNjW3SaR2xnu7j6pjbCiNvLNdmXG9bdNJzJDxZqmn72ceZvJZtrDgotwse97jl/cxWqh93jnNLjY9XeXUu4ylbxXW49wytfUjff7WPbkXXdBuNjMf3ku94eItsOu/DCxe5/l3F+LPdjR8zwKoW639+RS7gt7Z++ZhLBi+tE6a6HRwBsNvNHAGw280cAbDbzRwBsNPETgff/8c/3l6bfX1355+POl/P+f7P/n1n17/L7239/8ufs8Ztf/fWr+mP/P/rrvL+vrbP59m1/39Wf/vh/T///y/vb102R/u9/b4///3m4v9+/D9vof7+bv/zX7v2bdr375Xe//6DOe7GOObudnAAAdRZxfbAoAAA=='))
```

Simply running the code yields us garbled nonsense. But we can quickly identify the magic bytes from the output, being `1f 8b 08 00`, which is yet another gzip-compressed data. This ended up being a bit repetitive, and at the end the final result turned out to be quite long. Fortunately most of the bytes are null bytes and after stripping them we immediately yield our flag.

```python
import gzip; import base64; res = gzip.decompress(base64.b64decode('H4sIAAAAAAACA5Pv5mAAASbmt3cNuf9EzT3+sN5nQrdr2jIOrcbXJmHROjnJAouEuzN5jcq4Fbf6bN1wVlfNYInA9KvHri/k2HjhUVbxzHOHlB5vNdhWdDOpzPyo0Yy7S+6LFzyoXBVc/0r/+ffe+TVfEr8u/dF93/3if9td8//+Ff//8WK4HQMUNL7+V9J/3fBA+2Ojea/lmaCiC7PLMzf1Mt3zjTvJCBU6+Pp00v6/Ah92xQpbQoUUKm7azN2meyBZkk/cFi52vlpmbXQD0LhshLq3er7XdB2+533y4oOKccTFi/1+63HgdZnvE6hQw4PUzyW3tjH0p1rEfIGL2b4v3JLH2He6Yt1TuNjW3SaR2xnu7j6pjbCiNvLNdmXG9bdNJzJDxZqmn72ceZvJZtrDgotwse97jl/cxWqh93jnNLjY9XeXUu4ylbxXW49wytfUjff7WPbkXXdBuNjMf3ku94eItsOu/DCxe5/l3F+LPdjR8zwKoW639+RS7gt7Z++ZhLBi+tE6a6HRwBsNvNHAGw280cAbDbzRwBsNPETgff/8c/3l6bfX1355+POl/P+f7P/n1n17/L7239/8ufs8Ztf/fWr+mP/P/rrvL+vrbP59m1/39Wf/vh/T///y/vb102R/u9/b4///3m4v9+/D9vof7+bv/zX7v2bdr375Xe//6DOe7GOObudnAAAdRZxfbAoAAA=='))

while (res := gzip.decompress(res)).startswith(b'\x1f\x8b'):
    pass

assert len(res := res.replace(b'\0', b'')) < 0x40
print(res.decode())
```

```
flag{760671da3ca23cae060262190c01e575873c72e6}
```
