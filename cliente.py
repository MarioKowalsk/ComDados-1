import socket
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import PySimpleGUI as ps

#localhost
#HOST = "127.0.0.1"
#Endereço IP do servidor
HOST = "192.168.0.152"
#Porta do servidor
PORT = 24756
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
    pre = []
    for i in range(1, len(msg) + 1):
        pre.append(int.from_bytes(msg[i - 1:i], byteorder='big', signed=True))
    pos = []
    for i in range(len(pre)):
        #Se for algo diferente de zero, significa que foi alterado pelo AMI e que é preciso voltar o bit para 1
        if pre[i] != 0:
            pos.append(1)
        #Se for 0, então se mantem em 0 uma vez que o AMI não muda os zeros
        else:
            pos.append(0) 
    #Mostra os graficos do sinal pre e pós AMI inverso
    #Mostra somente os primeiros 24 sinais para evitar aglomeramento
    figure, axis = plt.subplots(2)
    axis[0].step(np.arange(0, min(len(pre), 24)), pre[0:min(len(pre), 24)], where='pre')
    axis[1].step(np.arange(0, min(len(pos), 24)), pos[0:min(len(pos), 24)], where='pre')
    #Versão para todos os pontos
    #axis[0].step(np.arange(0, len(pre)), pre, where='post')
    #axis[1].step(np.arange(0, len(pos)), pos, where='post')
    axis[0].set_ylim([-SIGNAL - 1, SIGNAL + 1])
    axis[1].set_ylim([2, -1])
    axis[0].set_title("Pre-AMI Inverso")
    axis[1].set_title("Pós-AMI Inverso")
    axis[0].set_yticks([-SIGNAL, 0, SIGNAL], minor=False)
    #if(pos[0] == 1):
    axis[1].invert_yaxis()
    axis[1].set_yticks([0, 1], minor=False)
    axis[0].grid(True, which="major")
    axis[1].grid(True, which="major")
    plt.show()  
    return pos

# Função para converter uma string de bits para bytes
# Retirada de https://stackoverflow.com/a/32676625
def bitstring_to_bytes(s):
    #Converte o arrays de bits para int usando base 2, depois converte esse int para bytes.
    #O tamanho da mensagem e bytes é o número de bit dividido por 8, já que tem 8 bits por byte
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
    
    layout = [[ps.Text('Conexão encontrada, aguardando mensagem', key="text1")],
              [ps.Multiline('placeholder', key='recv', visible=False, size=(150, 5))],
              [ps.Multiline('placeholder', key='dec', visible=False, size=(150, 5))],
              [ps.Multiline('placeholder', key='byte', visible=False, size=(150, 5))],
              [ps.Multiline('placeholder', key='decryp', visible=False, size=(150, 2))],
              [ps.Multiline('placeholder', key='final', visible=False, size=(150, 2))],
              [ps.Button("Close", key="close", visible=False)]
              ]
    window = ps.Window('Cliente AMI', layout)
    window.refresh()
    window.read(timeout=1000)
    
    window['text1'].update(visible=False)
    ONLY_AMI = c.recv(1)
    ONLY_AMI = int.from_bytes(ONLY_AMI, "big")
    
    msg = c.recv(2048)
    if(ONLY_AMI):
        window['recv'].widget.config(wrap='word')
        window['recv'].update(f"Mensagem recebida: {str(msg)}", visible=True)
        
        msg = decodeAMI(msg)
        arr = ''.join(str(x) for x in msg)
        arr = '0b' + arr
        window['dec'].widget.config(wrap='word')
        window['dec'].update(f"Mensagem pós-AMI: {str(arr)}", visible=True)
    
    else:
        window['recv'].widget.config(wrap='word')
        window['recv'].update(f"Mensagem recebida: {str(msg)}", visible=True)
        print("Mensagem recebida: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = decodeAMI(msg)
        arr = ''.join(str(x) for x in msg)
        arr = '0b' + arr
        window['dec'].widget.config(wrap='word')
        window['dec'].update(f"Mensagem pós-AMI: {str(arr)}", visible=True)
        print("Mensagem pós-AMI: " + str(arr) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = bitstring_to_bytes(arr)
        window['byte'].widget.config(wrap='word')
        window['byte'].update(f"Mensagem em bytes: {str(msg)}", visible=True)
        print("Mensagem em bytes: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = decodificar(msg)
        window['decryp'].widget.config(wrap='word')
        window['decryp'].update(f"Mensagem descriptografada: {str(msg)}", visible=True)
        print("Mensagem descriptografada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = msg.decode('utf-8')
        window['final'].widget.config(wrap='word')
        window['final'].update(f"Mensagem traduzida: {str(msg)}", visible=True)
        print("Mensagem traduzida: " + str(msg))
    
    window['close'].update(visible=True)
    while True:
        event, values = window.read()
        if event == ps.WIN_CLOSED or "close":
            break
    window.close()

if __name__ == "__main__":
    main()