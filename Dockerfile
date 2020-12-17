FROM ccr.ccs.tencentyun.com/debian/oldstable:slim
LABEL maintainer="cheny.roger@gmail.com"

COPY main /app/yunjiasu
COPY sources.list /etc/apt/sources.list

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

CMD ["/app/yunjiasu"]

# FROM golang:1.13.12-alpine3.12 AS build_deps
# WORKDIR /mnt
# ENV GO111MODULE=on
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && apk add --no-cache git && git clone https://github.com/chenyu116/yunjiasu-sync.git . && ls -la \
# && export GOPROXY=https://goproxy.io && go mod download

# FROM build_deps AS build
# COPY . .
# RUN CGO_ENABLED=0 go build -o yunjiasu-alpine -ldflags '-w -extldflags "-static"' .
# FROM ccr.ccs.tencentyun.com/astatium.com/alpine:3.11.5
# COPY --from=build /mnt/yunjiasu-alpine /app/yunjiasu-alpine
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && apk add --no-cache ca-certificates tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
#     && echo "Asia/Shanghai" > /etc/timezone \
#     && apk del tzdata

# CMD ["/app/yunjiasu-alpine"]