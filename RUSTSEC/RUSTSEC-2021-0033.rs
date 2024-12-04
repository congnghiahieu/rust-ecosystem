// Before

pub fn push_cloned(&mut self, v: &[T]) -> Result<(), ()> {
    self.push_inner(&v).map(|d| unsafe {
        let mut ptr = d.as_mut_ptr() as *mut T;
        for val in v {
            ptr::write(ptr, val.clone());
            ptr = ptr.offset(1);
        }
    })
}

// After

pub fn push_cloned(&mut self, v: &[T]) -> Result<(), ()> {
    let (meta, d) = self.push_inner(&v)?;
    // Prepare the slot with zeros (as if it's an empty slice)
    // The length is updated as each item is written
    // - This ensures that there's no drop issues during write
    meta[0] = 0;
    for v in d.iter_mut() {
        *v = 0;
    }
    unsafe {
        let mut ptr = d.as_mut_ptr() as *mut T;
        for val in v {
            ptr::write(ptr, val.clone());
            meta[0] += 1;
            ptr = ptr.offset(1);
        }
    }
    Ok(())
}
