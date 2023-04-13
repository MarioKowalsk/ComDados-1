import socket
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#localhost
#HOST = "127.0.0.1"
#Endereço IP do servidor
HOST = "192.168.0.152"
#Porta do servidor
PORT = 65432
#Tamanho da chave assimetrica
KEY_SIZE = '1024'
SIGNAL = 2

#Função para descriptografar usando chaves RSA retirada da documebtação da biblioteca PyCrypto
def decodificar(msg):
    #Importa a chave de um arquivo
    key = RSA.importKey(open('private' + KEY_SIZE + '.pem').read())
    #Cria uma cifra usando essa chave
    cipher = PKCS1_OAEP.new(key)
    #Decodifica a mensagem usando a cifra
    return cipher.decrypt(msg)

def decodeAMI(msg):
    pre = list(msg)
    pos = []
    for i in range(len(pre)):
        #Se for algo diferente de zero, significa que foi alterado pelo AMI e que é preciso voltar o bit para 1
        if pre[i] != 0:
            pos.append(1)
            if pre[i] == 254:
                pre[i] = -SIGNAL
        #Se for 0, então se mantem em 0 uma vez que o AMI não muda os zeros
        else:
            pos.append(0) 
    #Mostra os graficos do sinal pre e pós AMI inverso
    #Mostra somente os primeiros 24 sinais para evitar aglomeramento
    figure, axis = plt.subplots(2)
    axis[0].step(np.arange(0, 24), pre[0:24], where='post')
    axis[1].step(np.arange(0, 24), pos[0:24], where='post')
    #Versão para todos os pontos
    #axis[0].step(np.arange(0, len(pre)), pre, where='post')
    #axis[1].step(np.arange(0, len(pos)), pos, where='post')
    axis[0].set_ylim([2.5, -2.5])
    axis[0].set_title("Pós-AMI")
    axis[1].set_title("Pre-AMI")
    axis[0].set_yticks([SIGNAL, 0, -SIGNAL], minor=False)
    axis[1].set_yticks([0, 1], minor=False)
    axis[0].grid(True, which="major")
    axis[1].grid(True, which="major")
    plt.show()  
    return pos

# Função para converter uma string de bits para bytes
# Retirada de https://stackoverflow.com/a/32676625
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])            

def main():
    #Cria um socket com o endereço IP e porta configuradas
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((HOST, PORT))
    
    msg = c.recv(2048)
    print("Mensagem recebida: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = decodeAMI(msg)
    arr = ''.join(str(x) for x in msg)
    print("Mensagem pós-AMI: " + str(arr) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = bitstring_to_bytes(arr)
    print("Mensagem em bytes: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = decodificar(msg)
    print("Mensagem descriptografada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    msg = msg.decode('utf-8')
    print("Mensagem traduzida: " + str(msg))

if __name__ == "__main__":
    main()