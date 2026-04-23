// Licensed under the Apache-2.0 license

use crate::exit_on_drop::ExitOnDrop;
use crate::*;
use core::cell::Cell;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use pin_project_lite::pin_project;

pin_project! {
    /// A convenient handle for making subscribe and/or allow syscalls and providing a slot for
    /// holding the upcall result.
    pub struct TockSubscribe<S: Syscalls> {
        // Safety: pinning is required here since the upcall will store the result.
        #[pin]
        result: Cell<Option<(u32, u32, u32)>>,
        error: Option<ErrorCode>,
        _syscall: PhantomData<S>,
        _pinned: PhantomPinned,
    }

    impl<S: Syscalls> PinnedDrop for TockSubscribe<S> {
        fn drop(this: Pin<&mut Self>) {
            if this.result.get().is_none() && this.error.is_none() {
                panic!("The TockSubscribe future was dropped before the upcall happened.");
            }
        }
    }
}

impl<S: Syscalls> Default for TockSubscribe<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> TockSubscribe<S> {
    pub fn new() -> TockSubscribe<S> {
        TockSubscribe {
            result: Cell::new(None),
            error: None,
            _syscall: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    fn set_err(self: Pin<&mut Self>, err: ErrorCode) {
        let this = self.project();
        *this.error = Some(err);
    }

    pub fn subscribe_allow_rw<C: allow_rw::Config>(
        mut self: Pin<&mut Self>,
        driver_num: u32,
        subscribe_num: u32,
        buffer_num: u32,
        buffer: &mut [u8],
    ) {
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*self as *const TockSubscribe<S>) as usize;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RW }>([
                driver_num.into(),
                buffer_num.into(),
                buffer.as_mut_ptr().into(),
                buffer.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }
    }

    pub fn subscribe_allow_ro<C: allow_ro::Config>(
        mut self: Pin<&mut Self>,
        driver_num: u32,
        subscribe_num: u32,
        buffer_num: u32,
        buffer: &[u8],
    ) {
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*self as *const TockSubscribe<S>) as usize;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RO }>([
                driver_num.into(),
                buffer_num.into(),
                buffer.as_ptr().into(),
                buffer.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }
    }

    pub fn subscribe_allow_ro_rw<C: allow_rw::Config>(
        mut self: Pin<&mut Self>,
        driver_num: u32,
        subscribe_num: u32,
        buffer_ro_num: u32,
        buffer_ro: &[u8],
        buffer_rw_num: u32,
        buffer_rw: &mut [u8],
    ) {
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*self as *const TockSubscribe<S>) as usize;

        // Allow RO
        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RO }>([
                driver_num.into(),
                buffer_ro_num.into(),
                buffer_ro.as_ptr().into(),
                buffer_ro.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_ro_num);
        }

        // Allow RW
        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RW }>([
                driver_num.into(),
                buffer_rw_num.into(),
                buffer_rw.as_mut_ptr().into(),
                buffer_rw.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_rw_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }
    }

    pub fn subscribe(mut self: Pin<&mut Self>, driver_num: u32, subscribe_num: u32) {
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*self as *const TockSubscribe<S>) as usize;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                self.as_mut()
                    .set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                self.as_mut().set_err(ErrorCode::Fail);
            }
        }
    }

    /// TODO: Handle timeout.
    /// Block on the upcall until it returns a result.
    pub fn poll(self: Pin<&mut Self>) -> Result<(u32, u32, u32), ErrorCode> {
        loop {
            match self.result.get() {
                Some(tuple) => return Ok(tuple),
                None => S::yield_wait(),
            }
        }
    }

    /// Cancel the subscription, set error so that it is gracefully dropped.
    pub fn cancel(self: Pin<&mut Self>) {
        self.set_err(ErrorCode::Fail);
    }
}

extern "C" fn kernel_upcall<S: Syscalls>(arg0: u32, arg1: u32, arg2: u32, data: Register) {
    let exit: ExitOnDrop<S> = Default::default();
    let upcall: *mut TockSubscribe<S> = data.into();
    // Safety: we set the pointer to a pinned TockSubscribe instance in the subscribe.
    // If the subscribe call had failed, then the error would have been set this upcall
    // will never be called.
    // If the reference to the TockSubscribe is dropped before the upcall, then we panic
    // in the Drop instead of dereferencing into an invalid pointer.
    unsafe { (*upcall).result.set(Some((arg0, arg1, arg2))) };
    core::mem::forget(exit);
}
