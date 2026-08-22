# qubit-redact-derive 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [运行时用户手册](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.zh_CN.md)

本 crate 提供 `#[derive(Redact)]` 宏。运行时负责策略、预算和掩码；生成的实现只描述
领域值如何通过 `RedactionWriter` 写出。

## 安装

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["derive"] }
qubit-redact-derive = "0.5"
```

生成代码要求 `qubit-redact` 是直接依赖，也支持 Cargo 重命名。使用
`#[redact(serde)]` 时启用运行时 `serde` feature 并直接添加 `serde`；使用
`#[redact(json)]` 时启用 `json` feature。

## 基本脱敏

```rust
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Login {
    account: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    recovery_code: String,
}

let login = Login {
    account: "ada".into(),
    password: "raw-password".into(),
    recovery_code: "never-render".into(),
};
let output = Redactor::standard().redact(&login);
assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
assert!(!output.text().as_str().contains("never-render"));
assert_eq!(login.password, "raw-password");
```

源对象只被借用且保持不变。需要自定义策略时使用
`Redactor::new(policy).redact(&value)`。生成的运行时实现只有一个
`Redact::write_redacted` 方法，不存在可变脱敏 trait。

## 字段模式

| 模式 | 含义 |
| --- | --- |
| 无属性 | 使用普通 `Debug` 输出，不推断敏感度。 |
| `level = "low"`、`"medium"`、`"high"`、`"secret"` | 按指定敏感等级掩码。 |
| `skip` | 省略字段。 |
| `nested` | 委托给嵌套值的 `Redact` 实现。 |
| `map` | 对支持的文本 key Map 按 key 和策略处理。 |
| `json` | 对支持的 JSON 文本递归处理。 |

已移除的 `plain`、`no_mut` 和 `require_explicit` 属性会被拒绝。只有在普通
`Debug` 输出经过明确审查时才保留未标注字段。宏支持具名、tuple、unit struct 和 enum
variant 的这些形态。

## 格式化与 Serde

容器属性需要显式启用：

```rust
#[derive(Redact)]
#[redact(debug, display, serde)]
struct Event {
    name: String,
    #[redact(level = "secret")]
    token: String,
}
```

`debug` 和 `display` 为原类型生成策略感知的格式化实现；`serde` 生成策略感知的
`Serialize`，不生成反序列化实现。序列化表示仍以字段模式为准，`skip` 仍然省略。
只有不会通过脱敏模式观察原始值的位置才允许序列化适配器。

## 解析 JSON 值

运行时也支持借用 `serde_json::Value`，且不会修改它：

```rust
let value = serde_json::json!({"password": "raw", "visible": "shown"});
let output = Redactor::standard().redact_json_value(&value);
let inspection = Redactor::standard().inspect_json_value(&value);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(value["password"], "raw");
let _ = inspection;
```

批量处理时可使用 `RedactionBatch::redact_json_value`，在一批值之间共享预算和摘要。

## 安全与审查清单

- 逐一审查未标注字段；derive 不会推断业务敏感度。
- `skip` 只是省略输出，不是内存擦除。
- 在无关日志和序列化路径中继续保护源值。
- 子系统需要隔离策略时使用显式 `Redactor`，不要依赖全局默认值。
- 发布前运行 `cargo test --all-features`、`./align-ci.sh` 和 `./ci-check.sh`。

参见 [API 文档](https://docs.rs/qubit-redact-derive) 与[运行时手册](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.zh_CN.md)。

## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。
