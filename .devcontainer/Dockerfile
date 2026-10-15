# Ambiente de desenvolvimento do envmem.
# Roda dentro do Docker Engine do WSL. O container é Linux, então o
# syscall.Exec funciona normalmente aqui dentro.
FROM golang:1.26

# O projeto não usa cgo (binários estáticos, sem depender de headers C).
ENV CGO_ENABLED=0

# Ferramentas do dia a dia:
#   postgresql-client: psql, usado na demonstração (mostrar o valor ilegível)
#   openssl: geração dos certificados da CA própria (Fatia 3)
#   make, git, curl: build, versionamento e instalação do Claude Code
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      postgresql-client openssl make git curl ca-certificates sudo \
 && rm -rf /var/lib/apt/lists/*

# Usuário comum (não root). Também será útil para a validação de que um
# usuário sem privilégio não lê o ambiente de outro processo.
ARG USERNAME=dev
ARG UID=1000
RUN useradd -m -u ${UID} -s /bin/bash ${USERNAME} \
 && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
 && mkdir -p /go/pkg/mod /home/${USERNAME}/.claude \
 && chown -R ${USERNAME}:${USERNAME} /go /home/${USERNAME}

USER ${USERNAME}
ENV PATH="/home/${USERNAME}/.local/bin:/go/bin:${PATH}"

# Ferramentas Go: migrações (goose) e verificação de vulnerabilidades.
RUN go install github.com/pressly/goose/v3/cmd/goose@latest \
 && go install golang.org/x/vuln/cmd/govulncheck@latest

# Claude Code. O login fica guardado no volume montado em ~/.claude
# (ver docker-compose.yml), então não se perde quando o container é recriado.
ENV CLAUDE_CONFIG_DIR=/home/${USERNAME}/.claude
RUN curl -fsSL https://claude.ai/install.sh | bash

WORKDIR /workspaces/envmem
