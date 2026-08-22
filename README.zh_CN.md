# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact-derive/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact-derive/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact-derive/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact-derive/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact-derive` 为 [`qubit-redact`](https://crates.io/crates/qubit-redact)
提供 `#[derive(Redact)]` 过程派生宏。它把经过审查的字段属性转换为策略感知的
`Redact::write_redacted` 实现。derive 不会修改源对象，也不提供可变脱敏 API。

## 快速开始

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["derive"] }
qubit-redact-derive = "0.5"
```

```rust
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    recovery_code: String,
}

let value = Credentials {
    user: "ada".into(),
    password: "raw-password".into(),
    recovery_code: "never-render".into(),
};
let output = Redactor::standard().redact(&value);
assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
assert!(!output.text().as_str().contains("never-render"));
```

未标注字段使用普通 `Debug` 输出，不会被推断为敏感字段，也不会递归遍历；所有跨越
脱敏边界的字段都必须明确审查。

## 字段模式

| 属性 | 行为 |
| --- | --- |
| 无属性 | 使用普通 `Debug` 输出。 |
| `#[redact(level = "low"\|"medium"\|"high"\|"secret")]` | 按指定敏感等级掩码。 |
| `#[redact(skip)]` | 从脱敏输出中省略。 |
| `#[redact(nested)]` | 委托给嵌套值的 `Redact` 实现。 |
| `#[redact(map)]` | 对支持的文本 key Map 按 key 和策略处理。 |
| `#[redact(json)]` | 对支持的 JSON 文本按 JSON key 递归处理。 |

`#[redact(plain)]`、`#[redact(no_mut)]` 和 `#[redact(require_explicit)]` 不属于当前契约。
宏支持具名、tuple、unit struct，以及 enum 的这些 variant 形态。容器属性
`#[redact(debug)]`、`#[redact(display)]` 和 `#[redact(serde)]` 都必须显式启用；Serde
支持还需要运行时 `serde` feature 和直接声明的 `serde` 依赖。

生成代码会解析直接声明的 `qubit-redact` 依赖，也支持 Cargo 重命名。运行时 trait 保持最小化：

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

## 安全边界

只有使用 `Redactor`、生成的格式化实现或生成的序列化实现的边界会受到保护。它不会擦除
源对象，也不能保护无关的日志和序列化路径。`skip` 只省略输出，源字段仍保留在内存中。
新增字段前必须复查其未标注语义。

需要借用且保持不变的解析 JSON，可使用运行时
`Redactor::redact_json_value(&serde_json::Value)` 或
`Redactor::inspect_json_value(&serde_json::Value)`。

## 开发

```bash
cargo test
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

参见[英文用户手册](doc/user_guide.md)、[中文用户手册](doc/user_guide.zh_CN.md)和
[运行时 crate](https://github.com/qubit-ltd/rs-redact)。

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
