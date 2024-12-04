pub struct MatrixSliceMut<'a, T: 'a> {
    ptr: *mut T,
}
pub struct RowMut<'a, T: 'a> {
    row: MatrixSliceMut<'a, T>,
}

impl<'a, T: 'a> RowMut<'a, T> {
    pub fn raw_slice_mut(&'_ mut self) -> &'a mut [T] {
        unsafe { from_raw_parts_mut(self.row.ptr, ..) }
    }
}
