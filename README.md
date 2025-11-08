# fileprotection
if you need immediate file protection or you are going to sell your old HDD, its better to encrypt your files before reinstaling the winodows

maybe the best way to build it is for 32bits system because its going to run on 64x too
GOOS=windows GOARCH=386 go build -ldflags="-s -w -H=windowsgui" -o filelocker-small.exe main.go
