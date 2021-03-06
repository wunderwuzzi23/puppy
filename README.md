# puppy - PCoIP Password Auth Testing Tooling

Test your organization's PCoIP server (e.g. Teradici) to uncover accounts with weak passwords by performing password spray testing.

Targeted API: `/pcoip-broker/xml`


# Usage

`puppy -domain example.org`

In addition the following three files have to be in the same directory as `puppy`:
1. `accounts.txt`
2. `passwords.txt`
3. `servers.txt` - only the first server is used at the moment

Runtime logs and results are written to the `./logs/` folder. 

# Get it

```
git clone https://github.com/wunderwuzzi23/puppy
```

or 

```
go get github.com/wunderwuzzi23/puppy
```

# Compile

```
go build -o puppy main.go
```

# Remarks

Security testing requires authorization from proper stakeholders before engaging.

