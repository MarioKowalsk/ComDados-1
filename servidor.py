import socket
import threading
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

HOST = "192.168.18.23"
PORT = 65432
KEY_SIZE = '1024'
SIGNAL = 2

#Função para criptografar usando chaves RSA retirada da documebtação da biblioteca PyCrypto
def criptografar(msg):
    #importar a chave de um arquivo
    key = RSA.importKey(open('public' + KEY_SIZE + '.pem').read())
    #cria uma cifra baseada na chave
    cipher = PKCS1_OAEP.new(key)
    #criptografa o texto que foi tranformado em bytes usando a ISO-8859-1
    ciphertext = cipher.encrypt(msg.encode('latin-1'))
    return ciphertext

#Função para aplicar o AMI à mensagem criptografada
def AMI(msg):
    #Função para tranformar a mensagem criptografada em binário
    msg = bin(int.from_bytes(msg, byteorder="big"))
    print("Mensagem em bits: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    pre = []
    pos = []
    sig = SIGNAL
    for i in range(2, len(msg)):
        pre.append(msg[i])
        #Se for um bit ligado, fica alternado entre um sinal positivo e negativo
        if (msg[i]) == '1':
            pos.append(sig)
            sig = -sig
        #Para bits desligados, nada é feito
        else:
            pos.append(0)
    #Mostra os graficos do sinal pre e pós AMI
    figure, axis = plt.subplots(2)
    axis[0].step(np.arange(0, 24), pre[0:24], where='post')
    axis[1].step(np.arange(0, 24), pos[0:24], where='post')
    axis[0].set_ylim([1.5, -0.5])
    axis[0].set_title("Pre-AMI")
    axis[1].set_title("Pós-AMI")
    plt.show()  
    return pos
        

def handle(conn, addr):
    msg = input("Mensagem a ser enviada: ")
    print("Mensagem pura: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = criptografar(msg)
    print("Mensagem criptografada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = AMI(msg)
    print("Mensagem codificada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    #Transforma o sinal pós-AMI em bytes para ser enviado pelo socket
    arr = msg[0].to_bytes(1, byteorder="big", signed=True)
    for i in range(1, len(msg)):
        arr += msg[i].to_bytes(1, byteorder="big", signed=True)
    print("Mensagem em bytes: " + str(arr))
    #Envia a mensagem
    conn.send(arr)


def main():
    #Cria um socket
    s =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Atriubuí a ele o IP e a Porta determinados
    s.bind((HOST, PORT))
    #Deixa ele esperando para conexões
    s.listen()
    
    #Fica escutando novas conexões
    #while True:
    #Aceita uma nova conexão
    conn, addr = s.accept()
    handle(conn, addr)
    #Começa uma nova thread para cada nova conexão
    #thread = threading.Thread(target=handle, args=(conn, addr))
    #thread.start()

if __name__ == "__main__":
    main()