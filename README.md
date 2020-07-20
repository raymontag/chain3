# Implementation of "iOS Exploit Chain 3"'s Kernel Part
## About
Ian Beer and Samuel Groß of Google Project Zero published a longer
serious about several in-the-wild caught iOS exploit chains. This
exploit takes chain 3[^1] and implementes the kernel exploit.

A full write-up about this exploit can be found at:

[https://secfault-security.com/blog/chain3.html](https://secfault-security.com/blog/chain3.html)

## Usage
For the development of this exploit an iPhone 5S with iOS 11.2.5 was used. Any
iPhone using the vulnerable driver and an iOS version below 11.4.1 should work.

It is suggested to use a Mac with Xcode installed as a build
system. In Xcode, a free signing identity for iPhone development is needed. Execute 
`security find-identity` in a terminal and find the fingerprint of
that identity. Copy the fingerprint into `Makefile` as the value for
the variable `SIGNING_ID`.

It is possible to use a jailbroken iPhone[^14] for development but it is
not necessary. A jailbroken has the advantage that no sandbox escape
is needed. Just remove the application overhead and turn the function
`exploit()` in the source code to the `main()` function. Copy the
correct entitlements via `ldid` to the binary on the iPhone and copy
the binary to `/Applications/`. Start the app via SSH.

If no jailbreak is available, the following way works as well.

Export your certificate identities to a file that can be read
with `openssl`. Execute the following commands on a terminal:

```
security export -t identities -f pkcs12 -o certs -k login.keychain
openssl pkcs12 -in certs
```

Search for your iPhone development certificate and copy the value of
`OU`. This is the team identifier. Copy that value to all `XXX` in the
file `entitlements.plist`. The file has already the format that is
needed to exploit Siguza's sandbox escape[^15].

The exploit is now ready for building and installation.

Build the exploit with `make` and install it with `ideviceinstaller -i
chain3.ipa` from the same directory. It is possible that this will
fail. What helps most times: Build and install some demo application
via Xcode and trust the developer certificate via the `Settings` app
of the iPhone. Then it should be possible to install the exploit
application as well.

To run and debug it, two terminal windows are needed. Moreover, the
device support files for the correct iOS version are needed. These can
be found, e.g., via Github[^16]. In the first
window run `idevicesyslog | grep chain3`. This command will print the
debug messages of the exploit. In the second window run 
`ideviceimagemounter DeveloperDiskImage.dmg` and then 
`idevicedebug -d foxhound.chain3`. The exploit should start on the
iPhone and debug messages should appear in the first terminal windows.

## License
This project is licensed under the terms of the WTFPL license.

[^1]: https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-3.html
