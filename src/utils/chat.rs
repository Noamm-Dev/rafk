use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

use crate::config::ChatRule;

pub fn parse(json: &str) -> String {
    match serde_json::from_str::<Value>(json) {
        Ok(value) => {
            let mut out = String::new();
            append(&value, &mut out);
            strip_codes(&out)
        }
        Err(_) => strip_codes(json),
    }
}

fn append(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => out.push_str(text),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::Bool(flag) => out.push_str(&flag.to_string()),
        Value::Array(items) => items.iter().for_each(|item| append(item, out)),
        Value::Object(object) => {
            if let Some(text) = object.get("text").and_then(Value::as_str) { out.push_str(text) }
            if let Some(key) = object.get("translate").and_then(Value::as_str) {
                let args: Vec<String> = object.get("with").and_then(Value::as_array).map(|args| {
                    args.iter().map(|arg| {
                        let mut text = String::new();
                        append(arg, &mut text);
                        text
                    }).collect() 
                }).unwrap_or_default();
                out.push_str(&translate(key, &args));
            }
            if let Some(extra) = object.get("extra") { append(extra, out) }
        }
        Value::Null => {}
    }
}

fn translate(key: &str, args: &[String]) -> String {
    let template = match key {
        "chat.type.text" => "<%s> %s",
        "chat.type.announcement" => "[%s] %s",
        "chat.type.emote" => "* %s %s",
        "chat.type.admin" => "[%s: %s]",
        "multiplayer.player.joined" => "%s joined the game",
        "multiplayer.player.left" => "%s left the game",
        "disconnect.timeout" => "Timed out",
        "disconnect.spam" => "Kicked for spamming",
        "disconnect.kicked" => "Kicked by an operator",
        _ if args.is_empty() => return key.to_string(),
        _ => return format!("{key} {}", args.join(" ")),
    };

    let mut out = String::new();
    let mut args = args.iter();
    for (i, part) in template.split("%s").enumerate() {
        if i > 0 {
            out.push_str(args.next().map_or("", String::as_str));
        }
        out.push_str(part);
    }
    out
}

fn strip_codes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '§' {
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

struct Rule {
    pattern: Regex,
    reply: String,
    cooldown: Duration,
    last_fired: Option<Instant>,
}

pub struct AutoResponder {
    rules: Vec<Rule>,
}

impl AutoResponder {
    pub fn new(rules: &[ChatRule]) -> Result<Self> {
        let rules = rules.iter().map(|rule| {
            Ok(Rule {
                pattern: Regex::new(&rule.pattern).with_context(|| format!("invalid chat rule pattern {:?}", rule.pattern))?,
                reply: rule.reply.clone(),
                cooldown: Duration::from_secs(rule.cooldown_secs),
                last_fired: None,
            })
        }).collect::<Result<_>>()?;
        
        Ok(Self { rules })
    }

    /// First matching rule that is off cooldown wins; `$1` / `${name}` in the reply expand to captures.
    pub fn respond(&mut self, message: &str) -> Option<String> {
        let now = Instant::now();
        for rule in &mut self.rules {
            if rule.last_fired.is_some_and(|last| now.duration_since(last) < rule.cooldown) { continue }
            let Some(captures) = rule.pattern.captures(message) else { continue };

            let mut reply = String::new();
            captures.expand(&rule.reply, &mut reply);
            rule.last_fired = Some(now);
            return Some(reply);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_component_and_strips_codes() {
        let json = r#"{"text":"","extra":[{"text":"§b[MVP§c+§b] Steve","color":"aqua"},{"text":"§f: hello ","extra":["world"]}]}"#;
        assert_eq!(parse(json), "[MVP+] Steve: hello world");
    }

    #[test]
    fn parses_translate_with_args() {
        let json = r#"{"translate":"chat.type.text","with":[{"text":"Alex"},"hi"]}"#;
        assert_eq!(parse(json), "<Alex> hi");
    }

    #[test]
    fn falls_back_to_legacy_text() {
        assert_eq!(parse("§cYou are banned"), "You are banned");
        assert_eq!(parse(r#""§aplain string""#), "plain string");
    }

    #[test]
    fn responder_expands_captures_and_respects_cooldown() {
        let rules = [ChatRule {
            pattern: r"^From (?:\[[^\]]+\] )?(\w+): ".into(),
            reply: "/msg $1 I'm AFK".into(),
            cooldown_secs: 300,
        }];
        let mut responder = AutoResponder::new(&rules).unwrap();

        assert_eq!(
            responder.respond("From [VIP] Steve: you there?").as_deref(),
            Some("/msg Steve I'm AFK")
        );
        assert_eq!(responder.respond("From Alex: hello?"), None);
        assert_eq!(responder.respond("unrelated"), None);
    }
}
