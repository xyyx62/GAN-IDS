import os

def capture():
    print("hello world!")
    NAME = os.popen('python /home/xiaoyue/Pcap-Analyzer-master/app/capture.py')
    PCAP_NAME = NAME.read()
    A = str(PCAP_NAME)
    A = PCAP_NAME.rstrip()
    return A

#def honeypot():
#    NAME = os.popen('docker ')
#    PCAP_NAME = NAME.read()
#    A = str(PCAP_NAME)
#    A = PCAP_NAME.rstrip()
#    return A
if __name__ == '__main__':
    capture()
