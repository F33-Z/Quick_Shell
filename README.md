# Quick Shell
---
## About
---
` Qshell is a cammand line tool that provides you with the payload you want to gain a reverse/bind shell quickly and copy it directlly to your clipboard`

---
## Installation 
Required Dependencies : **xclip** 
```bash
  sudo apt-get install xclip
```

```bash
  sudo git clone https://github.com/F33-Z/Quick_Shell
  cd Quick_Shell
  chmod +x Qshell.sh
  ./Qshell.sh --help
```
---
## Help
to list the help menu
```bash
  Qshell --help
  Qshell -h
```

![help](img/help.png?raw=true) 

---

## List Shells
to list all reverse/bind shells
```bash
  Qshell --list
  Qshell -l
```

![list](img/list.png?raw=true) 

---

## Usage

### 1. reverse shell
* you need to provide your IP address and port number

```bash
  Qshell nc --lhost 10.10.10.10 --lport 9999
  Qshell nc -L 10.10.10.10 -P 9999
```
* to copy the payload to your clipboard 
```bash
  Qshell nc --lhost 10.10.10.10 --lport 9999 --clipboard
  Qshell nc -L 10.10.10.10 -P 9999 -c
```
* to change type of shell from **bash** to **sh** or **zsh**
```bash
  Qshell nc --lhost 10.10.10.10 --lport 9999 --clipboard --type sh
  Qshell nc -L 10.10.10.10 -P 9999 -c -t sh
```
### 2. bind shell
* you need to provide a port number

```bash
  Qshell nc --lport 9999 --bind
  Qshell nc -P 9999 -b
```
* to copy the payload to your clipboard 
```bash
  Qshell nc --lport 9999 --bind --clipboard 
  Qshell nc -P 9999 -b -c
```
* to change type of shell from **bash** to **sh** or **zsh**
```bash
  Qshell nc --lport 9999 --bind --clipboard --type sh
  Qshell nc -P 9999 -b -c -t sh
```

### PS : move the script Qshell.sh to a path in your PATH variable to make it easier and faster to run it from anywhere

```bash
  echo $PATH
  mv Qshell.sh /pathIn/yourPATHvariable/Qshell
```
