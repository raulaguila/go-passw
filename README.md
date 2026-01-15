# passguard

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Coverage](https://img.shields.io/badge/Coverage-90%25-brightgreen?style=flat-square)](.)

Biblioteca Go para validação e geração de senhas com políticas configuráveis via YAML e suporte a hot-reload.

## ✨ Características

- 🔐 **Validação configurável** - Políticas definidas em YAML
- 🎲 **Gerador de senhas** - Gera senhas seguras que atendem às políticas
- 🔄 **Hot-reload** - Atualiza políticas sem reiniciar a aplicação
- ⌨️ **Keyboard patterns** - Detecta padrões de teclado (qwerty, asdfgh)
- 📏 **Múltiplas regras** - Tamanho, entropia, sequências, categorias
- 🧩 **Extensível** - Adicione predicados customizados
- 🧵 **Thread-safe** - Seguro para uso concorrente
- ⏱️ **Context-aware** - Suporte a cancelamento e timeouts
- ⚡ **Fail-fast** - Modo de performance para validação rápida
- 📊 **Análise rica** - Score, entropia e sugestões de melhoria
- 📝 **Logger injetável** - Customize ou desabilite logs

## 📦 Instalação

```bash
go get github.com/raulaguila/passguard
```

## 🚀 Uso Rápido

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/raulaguila/passguard"
)

func main() {
    validator, err := passguard.New("policy.yaml")
    if err != nil {
        log.Fatal(err)
    }
    defer validator.Close()

    ctx := context.Background()
    errs := validator.Validate(ctx, "MinhaSenh@123")
    if len(errs) > 0 {
        fmt.Println("Senha inválida:", errs[0].Message)
    } else {
        fmt.Println("Senha válida!")
    }
}
```

## 📊 Análise Detalhada (Result)

```go
result := validator.Analyze(ctx, "MinhaSenh@123")

fmt.Printf("Válida: %t\n", result.Valid)
fmt.Printf("Score: %d/100\n", result.Score)
fmt.Printf("Força: %s\n", result.Strength)
fmt.Printf("Entropia: %.2f bits\n", result.Entropy)

// Para senhas fracas, veja as sugestões
if !result.Valid {
    for _, sugestao := range result.Suggestions {
        fmt.Println("-", sugestao)
    }
}
```

**Saída:**
```
Válida: true
Score: 85/100
Força: Very Strong
Entropia: 89.12 bits
```

## ⚡ Modo Fail-Fast

```go
// Para na primeira falha (mais rápido)
validator, _ := passguard.NewWithOptions("policy.yaml",
    passguard.WithFailFast(),
)

errs := validator.Validate(ctx, "abc")
// Retorna apenas o primeiro erro, não todos
```

## 📝 Logger Customizado

```go
// Com logger customizado
validator, _ := passguard.NewWithOptions("policy.yaml",
    passguard.WithAutoReload(),
    passguard.WithLogger(slog.Default()),
)

// Desabilitar logs completamente
validator, _ := passguard.NewWithOptions("policy.yaml",
    passguard.WithAutoReload(),
    passguard.WithLogger(nil),
)
```

## ⏱️ Com Timeout

```go
ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
defer cancel()

errs := validator.Validate(ctx, "MinhaSenh@123")
// Retorna CONTEXT_CANCELLED se expirar
```

## 🔄 Com Hot-Reload

```go
validator, _ := passguard.NewWithOptions("policy.yaml",
    passguard.WithAutoReload(),
)
defer validator.Close()

// Métricas de reload
metrics := validator.Metrics()
fmt.Printf("Reloads: %d\n", metrics.ReloadCount)
```

## ⚙️ Configuração (policy.yaml)

```yaml
policies:
  length:
    enabled: true
    min: 8
    max: 128

  entropy:
    enabled: true
    min_entropy: 60
    blacklist: [password, admin, 123456]
    blacklist_boost: 8

  sequence:
    enabled: true
    max_sequence: 3

  category:
    enabled: true
    rules:
      - { name: uppercase, min: 1, predicate: upper, enabled: true }
      - { name: lowercase, min: 1, predicate: lower, enabled: true }
      - { name: number, min: 1, predicate: number, enabled: true }
      - { name: special, min: 1, predicate: special, enabled: true }
```

## 🎲 Gerador de Senhas

```go
// Gerar senha segura que atende à política
password, err := validator.Generate(ctx)
// Exemplo: "Kx9#mPw$2nQr!Zt5"

// Com tamanho customizado
password, err := validator.Generate(ctx, passguard.WithLength(24))

// Excluir caracteres ambíguos (0, O, 1, l, I)
password, err := validator.Generate(ctx, passguard.WithExcludeAmbiguous())

// Combinando opções
password, err := validator.Generate(ctx,
    passguard.WithLength(20),
    passguard.WithExcludeAmbiguous(),
)
```

**Características do gerador:**
- Usa `crypto/rand` para aleatoriedade segura
- Garante pelo menos 1 caractere de cada categoria
- Valida senha gerada contra as políticas
- Performance: ~100k senhas/segundo

## 📋 Códigos de Erro

| Código | Descrição |
|--------|-----------|
| `LENGTH_TOO_SHORT` | Senha menor que o mínimo |
| `LENGTH_TOO_LONG` | Senha maior que o máximo |
| `LOW_ENTROPY` | Entropia insuficiente |
| `SEQUENCE_TOO_LONG` | Sequência previsível detectada |
| `KEYBOARD_PATTERN` | Padrão de teclado detectado (qwerty, etc.) |
| `CATEGORY_MIN_NOT_MET` | Requisito de categoria não atendido |
| `CONTEXT_CANCELLED` | Validação cancelada via context |

## 🏷️ Predicados Disponíveis

| Predicado | Descrição |
|-----------|-----------|
| `upper` | Letras maiúsculas (A-Z) |
| `lower` | Letras minúsculas (a-z) |
| `number` | Dígitos (0-9) |
| `special` | Símbolos (!@#$%^&*) |
| `ascii` | Caracteres ASCII |
| `emoji` | Emojis básicos |

### Predicado Customizado

```go
import "github.com/raulaguila/passguard/rule"

rule.RegisterPredicate("vowel", func(r rune) bool {
    return strings.ContainsRune("aeiouAEIOU", r)
})
```

## 📁 Estrutura

```
passguard/
├── passguard.go          # API pública (New, Validate, Analyze)
├── config/               # Tipos e loader YAML
├── engine/               # Motor de validação + hot-reload
├── rule/                 # Implementações de regras
└── errors/               # Tipo ValidationError
```

## 🧪 Testes

```bash
go test ./... -v -cover
```

## 📄 Licença

MIT License

---

Desenvolvido com ❤️ por [@raulaguila](https://github.com/raulaguila)
