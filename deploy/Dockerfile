FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/zlog ./cmd/zlog

FROM alpine:3.22
RUN adduser -D -H -u 10001 zlog
USER zlog
COPY --from=build /out/zlog /usr/local/bin/zlog
EXPOSE 8088
ENTRYPOINT ["zlog"]
CMD ["serve-dashboard", "--addr", ":8088", "--dir", "/data/zlog"]
