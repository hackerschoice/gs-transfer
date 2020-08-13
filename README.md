# gs-transfer

An easy tool to securely transfer files between two computers behind NAT/Firewall. It use the Global Socket Network to circumvent the NAT/Firewall and SRP ([RFC 5054](https://tools.ietf.org/html/rfc5054)) with a 4096 Prime, AES-256 and SHA256.

![alt text](https://github.com/hackerschoice/gs-transfer/blob/master/img/gst-ss.png?raw=true)

**Features:**
- Does not require any User to open a port on their router or firewall.
- Does not require OpenSSH.
- Passwords are securily and randomly created.
- Passwords are only valid for 1 transfer.
- Both Users can be behind NAT.
- Uses outgoing connections (to the GS-Net) only.
- SRP Encryption is end-to-end (the GS-Net can not read the traffic).
- No PKI required.
- Uses 4096 Prime and AES-256 Bit encryption with SHA256.

**Installation**
```ShellSession
$ git clone https://github.com/hackerschoice/gs-transfer.git
$ cd gs-transfer && ./bootstrap && ./configure && make all
```

**Usage**

Receiver:
```ShellSession
$ ./gs-transfer
```

Sender:
```ShellSession
$ ./gs-transfer *.mp3 *.c
```


**SHOUTZ**
Thanks to g4- for testing. THIS IS ALPHA RELEASE. PLEASE TEST.
