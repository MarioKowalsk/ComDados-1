from socket import socket, gethostbyname, AF_INET, SOCK_STREAM
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import PySimpleGUI as ps
import textwrap

#localhost
#HOST = "127.0.0.1"
#Endereço IP a ser alocado
HOST = "192.168.0.152"
#Porta a ser alocada
PORT = 24756
#Tamanho da chave assimetrica
KEY_SIZE = '1024'
SIGNAL = 2

#Função para criptografar usando chaves RSA retirada da documebtação da biblioteca PyCrypto
def criptografar(msg):
    #importar a chave de um arquivo
    key = RSA.importKey(open('public' + KEY_SIZE + '.pem').read())
    #cria uma cifra baseada na chave
    cipher = PKCS1_OAEP.new(key)
    #criptografa o texto que foi tranformado em bytes usando a ISO-8859-1
    ciphertext = cipher.encrypt(msg.encode('utf-8'))
    return ciphertext

#Função para aplicar o AMI à mensagem criptografada
def AMI(msg, flag):
    if(flag == 0):
        #Função para tranformar a mensagem criptografada em binário
        msg = bin(int.from_bytes(msg, byteorder="big"))
        print("Mensagem em bits: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
    pre = []
    pos = []
    sig = SIGNAL
    for i in range(2, len(msg)):
        pre.append(msg[i])
        #Se for um bit ligado, fica alternado entre um sinal positivo e negativo
        if int(msg[i]) == 1:
            pos.append(sig)
            sig = -sig
        #Para bits desligados, nada é feito
        else:
            pos.append(0)
    #Mostra os graficos do sinal pre e pós AMI
    #Mostra somente os primeiros 24 sinais para evitar aglomeramento
    figure, axis = plt.subplots(2)
    axis[0].step(np.arange(0, min(len(pre), 24)), pre[0:min(len(pre), 24)], where='pre')
    axis[1].step(np.arange(0, min(len(pos), 24)), pos[0:min(len(pos), 24)], where='pre')
    #Versão para todos os pontos
    #axis[0].step(np.arange(0, len(pre)), pre, where='post')
    #axis[1].step(np.arange(0, len(pos)), pos, where='post')
    axis[0].set_ylim([2, -1])
    axis[1].set_ylim([-SIGNAL - 1, SIGNAL + 1])
    axis[0].set_title("Pre-AMI")
    axis[1].set_title("Pós-AMI")
    axis[0].set_yticks([0, 1], minor=False)
    #if(pre[0] == 1):
    axis[0].invert_yaxis()
    axis[1].set_yticks([-SIGNAL, 0, SIGNAL], minor=False)
    axis[0].grid(True, which="major")
    axis[1].grid(True, which="major")
    plt.show()
    return pos


def handle(conn, addr):
    ONLY_AMI = 0
    layout = [[ps.Text('Conexão encontrada', key="text1")],
              [ps.Text("Insira a mensagem a ser enviada", key="text2"), ps.Input(key="input")],
              [ps.Button("Enviar", key="send"), ps.Button("Teste Slides", key="only")],
              [ps.Multiline('placeholder', key='pure', visible=False, size=(100, 2))],
              [ps.Multiline('placeholder', key='crypto', visible=False, size=(150, 5))],
              [ps.Multiline('placeholder', key='cod', visible=False, size=(150, 5))],
              [ps.Multiline('placeholder', key='byte', visible=False, size=(150, 5))],
              [ps.Button("Close", key="close", visible=False)]
              ]
    window = ps.Window('Servidor AMI', layout)
    window.refresh()
    event, values = window.read()
    if(event == 'only'):
        ONLY_AMI = 1
        msg = '0b00010010'
        
        window['pure'].widget.config(wrap='word')
        window['pure'].update(textwrap.wrap(f"Mensagem pura: {str(msg)}"), visible=True)
        
        msg = AMI(msg, ONLY_AMI)
        window['cod'].widget.config(wrap='word')
        window['cod'].update(f"Mensagem codificada: {str(msg)}", visible=True)
        
        arr = msg[0].to_bytes(1, byteorder="big", signed=True)
        for i in range(1, len(msg)):
            arr += msg[i].to_bytes(1, byteorder="big", signed=True)
        window['byte'].widget.config(wrap='word')
        window['byte'].update(f"Mensagem em bytes: {str(arr)}", visible=True)
    else:
        msg = values['input']

        window['text2'].update(visible=False)
        window['input'].update(visible=False)
        window['send'].update(visible=False)
        window['text1'].update("Entrada recebida")

        window['pure'].widget.config(wrap='word')
        window['pure'].update(textwrap.wrap(f"Mensagem pura: {str(msg)}"), visible=True)
        print("Mensagem pura: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = criptografar(msg)
        window['crypto'].widget.config(wrap='word')
        window['crypto'].update(f"Mensagem criptografada: {str(msg)}", visible=True)
        print("Mensagem criptografada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        msg = AMI(msg, ONLY_AMI)
        window['cod'].widget.config(wrap='word')
        window['cod'].update(f"Mensagem codificada: {str(msg)}", visible=True)
        print("Mensagem codificada: " + str(msg) + '\n' + "--------------------------------------------------------------------------------------------------", end='\n\n')
        #Transforma o sinal pós-AMI em bytes para ser enviado pelo socket
        arr = msg[0].to_bytes(1, byteorder="big", signed=True)
        for i in range(1, len(msg)):
            arr += msg[i].to_bytes(1, byteorder="big", signed=True)
        window['byte'].widget.config(wrap='word')
        window['byte'].update(f"Mensagem em bytes: {str(arr)}", visible=True)
        print("Mensagem em bytes: " + str(arr))

    #Envia a mensagem
    conn.send(ONLY_AMI.to_bytes(1, byteorder="big"))
    conn.send(arr)
    window['close'].update(visible=True)
    while True:
        event, values = window.read()
        if event == ps.WIN_CLOSED or "close":
            break
    window.close()


def main():
    
    ps.theme('DarkAmber')	# Add a touch of color
    #Cria um socket
    s =  socket(AF_INET, SOCK_STREAM)
    #Atriubuí a ele o IP e a Porta determinados

    s.bind((HOST, PORT))
    #s.bind((hostName, PORT))

    print("Listening on " + str(HOST) + " " + str(PORT))
    #Deixa ele esperando para conexões
    s.listen()
    layout = [  [ps.Text('Esperando uma conexão')],
                [ps.Button('Cancel')] ]

    # # Create the Window
    #window = ps.Window('Servidor AMI', layout, finalize=True)
    # Event Loop to process "events" and get the "values" of the inputs
    conn, addr = s.accept()
    #window.close()
    handle(conn, addr)

    #Fica escutando novas conexões
    #while True:
    #Aceita uma nova conexão

    #Começa uma nova thread para cada nova conexão
    #thread = threading.Thread(target=handle, args=(conn, addr))
    #thread.start()

if __name__ == "__main__":
    main()