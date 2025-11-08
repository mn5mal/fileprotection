# fileprotection
if you need immediate file protection or you are going to sell your old HDD, its better to encrypt your files before reinstaling the winodows

Maybe the best way to build it for higher compatibility is to use an x86 system architecture rather than x64.
```
GOOS=windows GOARCH=386 go build -ldflags="-s -w -H=windowsgui" -o filelocker-small.exe main.go
```
