FROM python:3

RUN apt-get update && \
apt-get -y --no-install-recommends install automake libtool make gcc git python3-pip && \
rm -rf /var/lib/apt/lists/* && \
pip3 --no-cache-dir install yara-python && \
wget https://github.com/VirusTotal/yara/archive/v3.8.1.tar.gz -O yara.tar.gz && \
tar -zxf yara.tar.gz && \
rm yara.tar.gz

RUN cd yara-3.8.1 && \
./bootstrap.sh && \
./configure && \
make && \
make install

WORKDIR /usr/src/wait-for-it
RUN git clone --depth 1 https://github.com/vishnubob/wait-for-it . && \
chmod +x /usr/src/wait-for-it/wait-for-it.sh

WORKDIR /usr/src/pastehunter

COPY . ./
RUN pip3 --no-cache-dir install -r requirements.txt

CMD ["/usr/src/wait-for-it/wait-for-it.sh","-t", "0","172.16.10.10:9200","--", "python3", "pastehunter-cli"]

