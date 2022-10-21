# docker build -t thehunterctf:latest .
# docker run -it thehunterctf:latest /bin/bash


FROM ubuntu:20.04
LABEL maintainer="Jesper Mikkelsen"
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y python3.8-dev python3-pip libjansson-dev libmagic-dev p7zip-full p7zip-rar bsdmainutils wget nano git automake libtool make gcc pkg-config flex bison radare2 upx zip


WORKDIR /analyze

RUN git clone https://github.com/VirusTotal/yara.git

RUN cd yara && ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic --enable-dotnet && make && make install

RUN echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig

RUN wget https://github.com/jemik/RE-Challange/raw/main/XDR_ResponseApp_ProcessMemoryDump_ID00004921_20221020T072620Z.zip && 7z x -pv5aet5kj XDR_ResponseApp_ProcessMemoryDump_ID00004921_20221020T072620Z.zip

CMD yara -v