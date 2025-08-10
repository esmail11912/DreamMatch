FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache wget unzip \
 && wget -O pb.zip https://github.com/pocketbase/pocketbase/releases/download/v0.22.20/pocketbase_0.22.20_linux_amd64.zip \
 && unzip pb.zip && rm pb.zip
EXPOSE 8080
CMD ["./pocketbase", "serve", "--http=0.0.0.0:8080", "--dir", "/app/pb_data"]
