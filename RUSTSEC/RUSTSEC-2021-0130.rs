// https://github.com/jeromefroe/lru-rs/issues/120

pub struct LruEntry<K, V> {
    next: *mut LruEntry<K, V>,
}

pub struct LruCache<K, V> {
    head: *mut LruEntry<K, V>,
}

pub struct Iter<'a, K: 'a, V: 'a> {
    ptr: *const LruEntry<K, V>,
}

mod before {
    impl<K, V, S> LruCache<K, V, S> {
        pub fn iter<'a>(&'_ self) -> Iter<'a, K, V> {
            Iter {
                ptr: unsafe { (*self.head).next },
            }
        }
    }
}

mod after {
    impl<K, V, S> LruCache<K, V, S> {
        pub fn iter(&self) -> Iter<'_, K, V> {
            Iter {
                ptr: unsafe { (*self.head).next },
            }
        }
    }
}
