# Roteiro de Refatoração / Refactoring Roadmap

## Principais Problemas Identificados no Código Legado

### Problemas Arquiteturais

| Problema | Localização | Impacto |
|----------|-------------|---------|
| Responsabilidades misturadas | `policy.go` faz parsing E construção de regras | Difícil de testar e estender |
| Configuração não utilizada | Struct `Hashing` definido mas nunca usado | Código morto, API confusa |
| Acoplamento forte | Regras dependem diretamente do caminho do pacote errors | Estrutura inflexível |
| Sem injeção de dependências | `PolicyEngineReloadable` cria watcher internamente | Difícil de testar |
| Estado global mutável | `PredicateRegistry` é uma variável global | Preocupações com thread-safety |

### Problemas de Qualidade de Código

| Problema | Localização | Impacto |
|----------|-------------|---------|
| `fmt.Printf` para erros | `policy.go:47` | Sem logging estruturado |
| Tipos de receiver inconsistentes | Alguns pointer, alguns value | Padrões confusos |
| Mensagens de log hardcoded | `reloadable.go` | Sem personalização |
| Baixa cobertura de testes | Apenas 1 teste em `example_test.go` | Baixa confiança |
| Documentação ausente | Maioria dos tipos/funções exportados | Usabilidade ruim |
| Erro de tag YAML | `Argon2Config.Threads` tem tag errada `cost` | Bug de configuração |

### Práticas Ausentes

- Sem suporte a `context.Context` para cancelamento
- Sem shutdown gracioso para file watcher
- Sem validação de valores de configuração
- Sem padrão de opções para configuração flexível
- Nome de pacote `errors` sobrepõe biblioteca padrão

---

## Decisões Arquiteturais Tomadas

### 1. Separação por Camadas (Clean Architecture)

```
new/
├── passw.go              → API Pública (fachada simples)
├── config/               → Infraestrutura (I/O)
├── engine/               → Aplicação (orquestração)
├── rule/                 → Domínio (regras de negócio)
└── errors/               → Domínio (tipos de erro)
```

**Justificativa**: Cada camada tem responsabilidade clara, facilitando testes e manutenção.

### 2. Padrão de Opções Funcionais

```go
validator, err := passw.NewWithOptions("policy.yaml",
    passw.WithAutoReload(),
)
```

**Justificativa**: API flexível e extensível sem breaking changes.

### 3. Interface Rule com Name()

```go
type Rule interface {
    Name() string
    Validate(password string) *errors.ValidationError
}
```

**Justificativa**: Identificação para logging/métricas sem quebrar encapsulamento.

### 4. Registro de Predicados Thread-Safe

```go
func RegisterPredicate(name string, fn Predicate)
func GetPredicate(name string) Predicate
```

**Justificativa**: Permite extensibilidade com segurança de concorrência.

### 5. Shutdown Gracioso

```go
ctx, cancel := context.WithCancel(context.Background())
// ...
func (r *ReloadableEngine) Close() error {
    r.cancel()
    <-r.done
    return nil
}
```

**Justificativa**: Libera recursos corretamente ao finalizar a aplicação.

---

## Estratégia de Migração

### Fase 1: Estrutura Base ✅
- Criar `go.mod` com módulo novo
- Criar pacote `errors/` com `ValidationError`
- Criar pacote `rule/` com interface e predicados

### Fase 2: Implementação de Regras ✅
- Migrar `LengthRule` com mesma lógica
- Migrar `EntropyRule` com mesma lógica
- Migrar `SequenceRule` com mesma lógica
- Migrar `CategoryRule` com predicados thread-safe

### Fase 3: Engine e Configuração ✅
- Criar `config/` com tipos e loader
- Adicionar validação de configuração
- Criar `engine/` com `Engine` e `ReloadableEngine`

### Fase 4: API Pública ✅
- Criar `passw.go` como fachada
- Implementar padrão de opções funcionais
- Adicionar documentação completa

### Fase 5: Verificação ✅
- Criar testes unitários (23 testes, 85-94% cobertura)
- Validar compatibilidade com senhas de teste do legado
