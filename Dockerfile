# Stage 1: Build
FROM swift:5.10-jammy AS builder
WORKDIR /app
COPY . .
RUN swift build -c release --static-swift-stdlib

# Stage 2: Runtime
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libatomic1 libcurl4 libxml2 python3 python3-pip \
    && pip3 install fpdf2 holehe --break-system-packages \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/.build/release/Run .
COPY --from=builder /app/Sources/App/Plugins/sherlock_data.json Sources/App/Plugins/sherlock_data.json
COPY --from=builder /app/scripts scripts
COPY --from=builder /app/frontend frontend
EXPOSE 8080
ENTRYPOINT ["./Run", "serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
