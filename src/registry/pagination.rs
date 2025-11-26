pub fn paginate<T>(
    items: &[T],
    n: u16,
    continuation_token: Option<String>,
) -> (Vec<T>, Option<String>)
where
    T: Clone + ToString,
{
    let start = match continuation_token {
        Some(token) => match items.iter().position(|item| item.to_string() == token) {
            Some(pos) => pos + 1,
            None => 0,
        },
        None => 0,
    };

    let end = (start + n as usize).min(items.len());
    let result = items[start..end].to_vec();

    let next_token = if !result.is_empty() && end < items.len() {
        Some(result.last().unwrap().to_string())
    } else {
        None
    };

    (result, next_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginate_empty() {
        let items: Vec<String> = vec![];
        let (result, token) = paginate(&items, 10, None);
        assert!(result.is_empty());
        assert!(token.is_none());
    }

    #[test]
    fn test_paginate_all_items() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let (result, token) = paginate(&items, 10, None);
        assert_eq!(result.len(), 3);
        assert!(token.is_none());
    }

    #[test]
    fn test_paginate_first_page() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let (result, token) = paginate(&items, 2, None);
        assert_eq!(result, vec!["a", "b"]);
        assert_eq!(token, Some("b".to_string()));
    }

    #[test]
    fn test_paginate_second_page() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let (result, token) = paginate(&items, 2, Some("b".to_string()));
        assert_eq!(result, vec!["c"]);
        assert!(token.is_none());
    }

    #[test]
    fn test_paginate_invalid_token() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let (result, token) = paginate(&items, 2, Some("invalid".to_string()));
        assert_eq!(result, vec!["a", "b"]);
        assert_eq!(token, Some("b".to_string()));
    }
}
