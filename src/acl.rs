use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRule {
    pub pattern: String,
    pub access: Vec<String>,
    pub publish: Vec<String>,
    pub unpublish: Vec<String>,
    pub proxy: Option<String>,
}

impl PackageRule {
    pub fn open(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            access: vec!["$all".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Acl {
    rules: Vec<PackageRule>,
}

impl Acl {
    pub fn new(mut rules: Vec<PackageRule>) -> Self {
        if rules.is_empty() {
            rules.push(PackageRule::open("**"));
        }
        Self { rules }
    }

    pub fn default_open() -> Self {
        Self::new(vec![PackageRule::open("**")])
    }

    pub fn rule_for(&self, package: &str) -> Option<&PackageRule> {
        self.rules
            .iter()
            .find(|rule| pattern_matches(&rule.pattern, package))
            .or_else(|| self.rules.last())
    }

    pub fn can_access(&self, package: &str, user: Option<&str>) -> bool {
        self.rule_for(package)
            .map(|rule| permits(&rule.access, user))
            .unwrap_or(true)
    }

    pub fn can_publish(&self, package: &str, user: Option<&str>) -> bool {
        self.rule_for(package)
            .map(|rule| permits(&rule.publish, user))
            .unwrap_or(false)
    }

    pub fn can_unpublish(&self, package: &str, user: Option<&str>) -> bool {
        self.rule_for(package)
            .map(|rule| permits(&rule.unpublish, user))
            .unwrap_or(false)
    }

    pub fn proxy_for(&self, package: &str) -> Option<&str> {
        self.rule_for(package)
            .and_then(|rule| rule.proxy.as_deref())
    }
}

fn permits(principals: &[String], user: Option<&str>) -> bool {
    if principals.is_empty() {
        return false;
    }

    principals.iter().any(|principal| match principal.as_str() {
        "$all" | "all" | "@all" => true,
        "$anonymous" | "@anonymous" => user.is_none(),
        "$authenticated" | "@authenticated" => user.is_some(),
        other => user == Some(other),
    })
}

fn pattern_matches(pattern: &str, package: &str) -> bool {
    if pattern == "**" {
        return true;
    }

    wildcard_match(pattern, package)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_with_wild = pattern.starts_with('*');
    let ends_with_wild = pattern.ends_with('*');

    let mut position = 0usize;

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if index == 0 && !starts_with_wild {
            if !text[position..].starts_with(part) {
                return false;
            }
            position += part.len();
            continue;
        }

        if index == parts.len() - 1 && !ends_with_wild {
            if let Some(idx) = text[position..].rfind(part) {
                let absolute = position + idx;
                if absolute + part.len() != text.len() {
                    return false;
                }
                position = absolute + part.len();
                continue;
            }
            return false;
        }

        if let Some(idx) = text[position..].find(part) {
            position += idx + part.len();
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::pattern_matches;

    #[test]
    fn matches_basic_patterns() {
        assert!(pattern_matches("**", "foo"));
        assert!(pattern_matches("@*/*", "@scope/foo"));
        assert!(!pattern_matches("@*/*", "foo"));
        assert!(pattern_matches("@private/*", "@private/auth"));
        assert!(!pattern_matches("@private/*", "@other/auth"));
        assert!(pattern_matches("private-*", "private-auth"));
        assert!(!pattern_matches("private-*", "public-auth"));
        assert!(pattern_matches("vue", "vue"));
        assert!(!pattern_matches("vue", "react"));
    }
}
