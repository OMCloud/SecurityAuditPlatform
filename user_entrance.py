from django.contrib.auth import authenticate
import getpass,os
import subprocess



class UserPortal(object):

    def __init__(self):
        self.user = None



    def user_auth(self):
        retry_count = 0
        while retry_count < 3:
            username = input("Username:").strip()
            if len(username) == 0: continue
            password = getpass.getpass("Password:").strip()
            if len(password) == 0: continue
            user = authenticate(username=username, password=password)
            if user:
                self.user = user
                return
            else:
                print("Invalid username or password")
            retry_count += 1
        else:
            exit("Retry too many attempts")




    def interactive(self):
        self.user_auth()
        if self.user:
            exit_flag = False
            while not exit_flag:
                for index, host_group in enumerate(self.user.host_groups.all()):
                    print("#########:",host_group.bind_hosts.all().count())
                    print("%s. %s[%s]" % (index, host_group.name, host_group.bind_hosts.all().count()))
                print("%s. Ungrouped Hosts[%s]" % (index+1, self.user.bind_hosts.select_related().count()))

                user_input = input("Choose Group:").strip()
                if len(user_input) == 0: continue
                if user_input.isdigit():
                    user_input = int(user_input)
                    if user_input >= 0 and user_input < self.user.host_groups.all().count():
                        selected_hostgroup = self.user.host_groups.all()[user_input]
                    elif user_input == self.user.host_groups.count():
                        selected_hostgroup = self.user
                    else:
                        print("invalid host group")
                        continue
                    while True:
                        for index, bind_host in enumerate(selected_hostgroup.bind_hosts.all()):
                            print("%s. %s(%s user:%s)" % (index,
                                                          bind_host.host.hostname,
                                                          bind_host.host.ip_addr,
                                                          bind_host.host_user.username))

                        user_input2 = input("Choose Host:").strip()
                        if len(user_input2) ==0: continue
                        if user_input2.isdigit():
                            user_input2 = int(user_input2)
                            if user_input2 >= 0 and user_input2 < selected_hostgroup.bind_hosts.all().count():
                                selected_bindhost = selected_hostgroup.bind_hosts.all()[user_input2]
                                print("logging host", selected_bindhost)
                                login_cmd = 'sshpass -p {password} ssh {user}@{ip_addr} -o "StrictHostKeyChecking no"'.format(password=selected_bindhost.host_user.password,
                                                                                                                                user=selected_bindhost.host_user.username,
                                                                                                                                ip_addr=selected_bindhost.host.ip_addr)
                                ssh_instance = subprocess.run(login_cmd, shell=True)
if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SecurityAuditPlatform.settings")
    import django
    django.setup()
    from audit import models


    portal = UserPortal()
    portal.interactive()



