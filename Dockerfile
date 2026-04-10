FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /fakeidp .

FROM alpine:3
RUN adduser -D -u 1000 app
USER app
COPY --from=builder /fakeidp /fakeidp
EXPOSE 8080
CMD ["/fakeidp", "-userstate", "/data/users.json"]
