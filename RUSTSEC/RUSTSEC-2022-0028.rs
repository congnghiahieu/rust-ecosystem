// https://github.com/neon-bindings/neon/issues/896

mod before {
    pub fn external<'a, C, T>(cx: &mut C, data: T) -> Handle<'a, Self>
    where
        C: Context<'a>,
        T: AsMut<[u8]> + Send,
    {
        // ...
    }
}

mod after {
    pub fn external<'a, C, T>(cx: &mut C, data: T) -> Handle<'a, Self>
    where
        C: Context<'a>,
        T: AsMut<[u8]> + Send + 'static,
    {
        // ...
    }
}
