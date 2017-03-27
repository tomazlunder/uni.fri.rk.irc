import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading
import collections
import time
import datetime
import ssl



PORT = 1234
HEADER_LENGTH = 2



def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message)) # preberi nekaj bajtov
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk # pripni prebrane bajte sporocilu

    return message

def receive_message(sock):
    header = receive_fixed_length_msg(sock, HEADER_LENGTH) # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    message_length = struct.unpack("!H", header)[0] # pretvori dolzino sporocila v int

    message = None
    if message_length > 0: # ce je vse OK
        message = receive_fixed_length_msg(sock, message_length) # preberi sporocilo
        message = message.decode("utf-8")

    return message

def send_message(sock, message):
    encoded_message = message.encode("utf-8") # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message # najprj posljemo dolzino sporocila, slee nato sporocilo samo
    sock.sendall(message)

# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock, client_addr, user):
    global clients
    global client_names

    while True: # neskoncna zanka
        try:
            msg_received = receive_message(client_sock)
        except:
            msg_received = None

        if not msg_received: # ce obstaja sporocilo
            break
        print("[RKchat] [" + client_addr[0] + ":" + str(client_addr[1]) + "] ("+user+"): " + msg_received)
        if msg_received[0] == "!":
            splitano = msg_received.split()
            prejemnik = (splitano[0])[1:]
            sporocilo = msg_received[(len(prejemnik)+2):]
            #print("Prejemnik: " + prejemnik + " Sporočilo: " + sporocilo)
            if prejemnik in client_names:
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                predpona = ("("+st+") " + user + " (pvt): ")
                sporocilo = predpona + sporocilo
                send_message(client_names[prejemnik], sporocilo)
            else:
                sporocilo = ("Napaka: " + prejemnik + " ni prijavljen.")
                send_message(client_names[user], sporocilo)

        else:
            ts = time.time()
            st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            predpona = ("("+st+") " + user + " (pub): ")
            msg_received = predpona + msg_received
            for client in clients:
                send_message(client, msg_received)  #.upper() ??

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove(client_sock)
        client_names.pop(user)
        print(user + " disconnencted")
        print("[system] we now have " + str(len(clients)) + " clients")
        client_sock.close()

#SSL
def setup_SSL_context():
    #uporabi samo TLS, ne SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    # certifikat je obvezen
    context.verify_mode = ssl.CERT_REQUIRED
    #nalozi svoje certifikate
    context.load_cert_chain(certfile="server.pem", keyfile="serverkey.pem")
    # nalozi certifikate CAjev, ki jim zaupas
    # (samopodp. cert. = svoja CA!)
    context.load_verify_locations('clients.pem')
    # nastavi SSL CipherSuites (nacin kriptiranja)
    context.set_ciphers('AES128-SHA')
    return context


# kreiraj socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

context = setup_SSL_context()
#ssl.wrap_socket(server_socket, keyfile=None, certfile=None, server_side=False, cert_reqs=CERT_NONE, ssl_version={see docs}, ca_certs=None, do_handshake_on_connect=True, suppress_ragged_eofs=True, ciphers=None)

# cakaj na nove odjemalce
print("[system] listening ...")
clients = set()
client_names = collections.defaultdict()
clients_lock = threading.Lock()
while True:
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        """
        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr))
        thread.daemon = True
        thread.start()
        """

        conn, addr = server_socket.accept()
        conn = context.wrap_socket(conn, server_side=True)

        with clients_lock:
            clients.add(conn)

        #ime uporabnika dobimo iz certifikata
        cert = conn.getpeercert()
        for sub in cert['subject']:
            for key, value in sub:
            # v commonName je ime uporabnika
                if key == 'commonName':
                    user = value
        print('Established SSL connection with: ', user)
        client_names[user]=conn


        thread = threading.Thread(target=client_thread, args=(conn, addr, user))
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break


print("[system] closing server socket ...")
server_socket.close()
