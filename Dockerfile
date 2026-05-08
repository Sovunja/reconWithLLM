# syntax=docker/dockerfile:1.6

# ============================================================
# Стадия 1: сборка Go-инструментов разведки.
# ============================================================
FROM golang:1.22-bookworm AS tools

ENV GOFLAGS=-trimpath \
    GO111MODULE=on \
    CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org,direct

# Каждый тул в отдельном RUN — кэш Docker не пересобирает остальные,
# если упал один. Ретраи на случай транзиентных ошибок proxy.golang.org.

# subfinder — пассивный сбор поддоменов.
RUN for i in 1 2 3; do \
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 && break || \
        echo "subfinder install failed, attempt $i/3, retrying in 10s..." && sleep 10; \
    done

# httpx — определение веб-сервисов и технологий.
RUN for i in 1 2 3; do \
        go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 && break || \
        echo "httpx install failed, attempt $i/3, retrying in 10s..." && sleep 10; \
    done

# hakrawler — простой надёжный краулер (заменил katana, который зависал
# на минифицированных Angular SPA при парсинге больших JS-чанков).
RUN for i in 1 2 3; do \
        go install github.com/hakluke/hakrawler@latest && break || \
        echo "hakrawler install failed, attempt $i/3, retrying in 10s..." && sleep 10; \
    done

# dnsx — DNS-разведка: A/AAAA/MX/TXT/NS/CNAME-записи.
# Используется для обнаружения почтовых сервисов (MX) и определения
# инфраструктуры (Google Workspace, Microsoft 365, Cloudflare и т.д.).
RUN for i in 1 2 3; do \
        go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1 && break || \
        echo "dnsx install failed, attempt $i/3, retrying in 10s..." && sleep 10; \
    done

# ============================================================
# Стадия 2: сборка приложения (ядро + модули).
# ============================================================
FROM golang:1.22-bookworm AS app

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/recon ./

# ============================================================
# Стадия 3: финальный runtime-образ.
# Минимальный Debian slim — только CA-сертификаты для HTTPS.
# ============================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Все Go-инструменты разведки.
COPY --from=tools /go/bin/subfinder /usr/local/bin/
COPY --from=tools /go/bin/httpx     /usr/local/bin/
COPY --from=tools /go/bin/hakrawler /usr/local/bin/
COPY --from=tools /go/bin/dnsx      /usr/local/bin/

# Наше приложение.
COPY --from=app /out/recon /usr/local/bin/recon

# Непривилегированный пользователь.
RUN useradd -r -u 10001 -m -d /home/recon recon && \
    mkdir -p /data && chown -R recon:recon /data
USER recon
WORKDIR /home/recon

VOLUME ["/data"]

ENTRYPOINT ["recon"]
