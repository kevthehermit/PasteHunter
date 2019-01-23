FROM python:3

RUN apt-get update && \
apt-get -y install automake libtool make gcc git python3-pip && \
pip3 install yara-python && \
wget https://github.com/VirusTotal/yara/archive/v3.8.1.tar.gz -O yara.tar.gz && \
tar -zxf yara.tar.gz

RUN cd yara-3.8.1 && \
./bootstrap.sh && \
./configure && \
make && \
make install

WORKDIR /usr/src/wait-for-it
RUN git clone https://github.com/vishnubob/wait-for-it . && \
chmod +x /usr/src/wait-for-it/wait-for-it.sh

WORKDIR /usr/src/pastehunter

COPY . ./
RUN pip3 install -r requirements.txt

CMD ["/usr/src/wait-for-it/wait-for-it.sh","-t", "0","172.16.10.10:9200","--", "python3", "pastehunter.py"]

