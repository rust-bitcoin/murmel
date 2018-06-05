use std::env::args;

// Returns key-value zipped iterator.
fn zipped_args() -> impl Iterator<Item = (String, String)> {
    let key_args = args()
        .filter(|arg| arg.starts_with("-"))
        .map(|mut arg| arg.split_off(1));
    let val_args = args().skip(1).filter(|arg| !arg.starts_with("-"));
    key_args.zip(val_args)
}

pub fn find_arg(key: &str) -> Option<String> {
    zipped_args()
        .find(|&(ref k, _)| k.as_str() == key)
        .map(|(_, v)| v)
}
