# BUILD
FROM abilioesteves/gowebbuilder:v1.0.0 as builder

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /whisper-client main.go

## PKG
FROM alpine

COPY --from=builder /whisper-client /


