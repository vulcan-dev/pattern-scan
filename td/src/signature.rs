pub struct Signature {
    pub name: String,
    pub pattern: String,
    pub mask: String,
    pub direct_ref: bool
}

impl Signature {
    pub fn new(name: &str, pattern: &str, mask: &str, direct_ref: bool) -> Signature {
        Signature {
            name: name.to_string(),
            pattern: pattern.to_string(),
            mask: mask.to_string(),
            direct_ref
        }
    }
}