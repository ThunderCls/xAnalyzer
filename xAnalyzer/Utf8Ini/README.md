# Utf8Ini
Small and simple INI Parser for UTF-8 data written in C++. Used in [x64dbg](http://x64dbg.com).

Basically it supports this:

```
[Section 1]
Key 1=Value 1
 Key 1 = "Value 2"
Key 2=" this string starts and ends with a space "

 ; comment line

[Section 2]
Key 1="this string contains a\nnewline and escaped characters \\ \\n "
Key 2 = I like Utf8Ini!
```
