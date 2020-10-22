FROM ccr.ccs.tencentyun.com/debian/oldstable:slim
LABEL maintainer="cheny.roger@gmail.com"

COPY main /app/yunjiasu
COPY sources.list /etc/apt/sources.list

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

CMD ["/app/yunjiasu"]
