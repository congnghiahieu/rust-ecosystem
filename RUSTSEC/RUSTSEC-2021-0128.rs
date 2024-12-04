pub struct InnerConnection {
    db: *mut ffi::sqlite3,
}
pub struct Connection {
    db: RefCell<InnerConnection>,
}

impl Connection {
    pub fn update_hook<'c, F>(&'c self, hook: Option<F>)
    where
        F: 'c,
    {
        self.db.borrow_mut().update_hook(hook);
    }
}
