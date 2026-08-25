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
| `keyed_by = key` | 用兄弟文本 key 对当前字段分类，语义等同一条 Map entry。 |
| `json` | 对支持的 JSON 文本递归处理。 |

已移除的 `plain`、`no_mut` 和 `require_explicit` 属性会被拒绝。只有在普通
`Debug` 输出经过明确审查时才保留未标注字段。宏支持具名、tuple、unit struct 和 enum
variant 的这些形态。

字段 capability 会在编译期检查。`level` 可递归处理 `Option`、`Vec`、数组和 tuple 中受
支持的标量叶子，保持容器形状并逐叶掩码；`nested` 支持叶子实现 `Redact` 的 `Option` 和
`Vec`；`map` 要求文本 key，并按每个 key 的策略递归处理 value 的标量叶子；`keyed_by`
仅可用于具名字段，被引用的兄弟 key 必须实现 `AsRef<str>`，value 使用与 `level` 相同的
递归标量 capability。standard policy 会放行未知 keyed value；如果未知 payload key 也必须
掩码，应显式配置敏感 key 或使用更严格的策略。`json` 支持 `String`、`str`、`&str`、
`Cow<str>` 及其受支持的可选形态，非法 JSON 会 fail-closed。启用模式下 `skip` 不访问字段，
禁用模式下恢复原字段。

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

结构化 REST 响应中的嵌套值仍保持对象和数组，而不会退化为脱敏后的 Debug 字符串：

```rust
use std::collections::BTreeMap;

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Profile {
    name: String,
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct ApiResponse {
    ok: bool,
    #[redact(level = "medium")]
    attempts: u32,
    #[redact(nested)]
    profiles: Option<Vec<Profile>>,
    #[redact(map)]
    attributes: BTreeMap<String, Vec<String>>,
    #[redact(json)]
    audit: String,
    #[redact(skip)]
    internal_note: String,
}

fn encode(response: &ApiResponse) -> serde_json::Result<String> {
    serde_json::to_string(response)
}
```

启用脱敏时，被掩码的数字和布尔标量叶子会序列化为 JSON string，`Option::None` 仍是
`null`。将 application-default policy 设为 disabled 后，原始 JSON 标量类型、map
value、nested 字段、JSON 文本和 skip 字段都会恢复。`skip_serializing_if` 总是查看原始
字段：非 skip 模式会先执行 predicate；启用的 `redact(skip)` 不调用 predicate；禁用
`redact(skip)` 后 predicate 恢复执行。`with` 与 `serialize_with` 只允许用于未标注或
skip 字段，不能与敏感模式组合。

直接 Serde 没有 `RedactionSummary` 返回通道。非法或超出结构预算的内容仍然
fail-closed；需要完成状态和详细原因时，应使用 `Redactor::redact` 并检查摘要。

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

## 启用与禁用输出

全局禁用属于启动边界，会有意恢复原值：

```rust
use qubit_redact::{RedactionPolicy, Redactor};

let mut policy = RedactionPolicy::disabled();
assert!(policy.is_disabled());
policy.set_disabled(false);
let redactor = Redactor::new(policy);
```

策略启用时，即使摘要为 `Truncated` 或 `Exhausted`，文本也应保持保密安全。只有完整性、
原因追踪和审计场景需要检查 summary，不要用它判断启用模式的文本是否可能包含秘密。
若 inspection 用于安全决策，分类不完整时应按敏感处理。

## 安全与审查清单

- 逐一审查未标注字段；derive 不会推断业务敏感度。
- `skip` 只是省略输出，不是内存擦除。
- 在无关日志和序列化路径中继续保护源值。
- 子系统需要隔离策略时使用显式 `Redactor`，不要依赖全局默认值。
- 发布前运行 `cargo test --all-features`、`./align-ci.sh` 和 `./ci-check.sh`。

参见 [API 文档](https://docs.rs/qubit-redact-derive) 与[运行时手册](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.zh_CN.md)。

## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。
