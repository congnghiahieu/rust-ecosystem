// https://github.com/slide-rs/atom/issues/13

mod before {
    unsafe impl<P> Send for Atom<P> where P: IntoRawPtr + FromRawPtr {}
    unsafe impl<P> Sync for Atom<P> where P: IntoRawPtr + FromRawPtr {}

    impl<T> IntoRawPtr for Arc<T> {
        #[inline]
        unsafe fn into_raw(self) -> *mut () {
            Arc::into_raw(self) as *mut _ as *mut ()
        }
    }
}

mod after {
    unsafe impl<P> Send for Atom<P> where P: IntoRawPtr + FromRawPtr + Send {}
    unsafe impl<P> Sync for Atom<P> where P: IntoRawPtr + FromRawPtr + Send {}

    impl<T> IntoRawPtr for Arc<T> {
        #[inline]
        unsafe fn into_raw(self) -> *mut () {
            Arc::into_raw(self) as *mut T as *mut ()
        }
    }
}
