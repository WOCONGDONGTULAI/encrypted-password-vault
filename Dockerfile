FROM python:3.12-alpine

LABEL org.opencontainers.image.title="encrypted-password-vault" \
      org.opencontainers.image.description="Zero-dependency encrypted password container"

WORKDIR /app
COPY vault.py /app/vault.py

# 远端密文地址可用 -e VAULT_URL=... 覆盖
ENV VAULT_URL="https://raw.githubusercontent.com/WOCONGDONGTULAI/encrypted-password-vault/main/vault.enc"
# 本地密文文件可通过挂载覆盖： -v "$PWD/vault.enc:/app/vault.enc"
ENV VAULT_FILE="/app/vault.enc"

ENTRYPOINT ["python3", "-u", "/app/vault.py"]
CMD ["list"]
