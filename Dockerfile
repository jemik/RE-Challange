# docker build -t thehunterctf:latest .
# docker run -it thehunterctf:latest /bin/bash


FROM ubuntu:20.04
LABEL maintainer="Jesper Mikkelsen"
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y python3.8-dev python3-pip libjansson-dev libmagic-dev p7zip-full p7zip-rar bsdmainutils wget nano git automake libtool make gcc pkg-config flex bison radare2 upx zip vim tmux

COPY requirements.txt /analyze/requirements.txt
WORKDIR /analyze

RUN git clone https://github.com/VirusTotal/yara.git

RUN cd yara && ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic --enable-dotnet && make && make install

RUN echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig

RUN wget https://github.com/jemik/RE-Challange/raw/main/XDR_ResponseApp_ProcessMemoryDump_ID00004921_20221020T072620Z.zip && 7z x -pv5aet5kj XDR_ResponseApp_ProcessMemoryDump_ID00004921_20221020T072620Z.zip

COPY requirements.txt /analyze/
COPY hexyara.py /analyze/
RUN pip3 install -r requirements.txt
RUN pyinstaller /analyze/hexyara.py --onefile
RUN cp /analyze/dist/hexyara /usr/bin/hexyara

RUN rm requirements.txt && rm *.py && rm -rf __pycache__ build dist && rm *.spec

CMD yara -v