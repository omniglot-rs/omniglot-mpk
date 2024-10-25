use crate::libc_bindings;

pub struct PkeyAlloc<A: std::alloc::GlobalAlloc> {
    pkey: std::sync::atomic::AtomicUsize,
    pkey_mut: std::sync::Mutex<bool>,
    alloc: A,
}

impl<A: std::alloc::GlobalAlloc> PkeyAlloc<A> {
    pub const fn new(alloc: A) -> Self {
        PkeyAlloc {
            pkey: std::sync::atomic::AtomicUsize::new(0),
            pkey_mut: std::sync::Mutex::new(false),
            alloc,
        }
    }

    pub fn get_pkey(&self) -> std::ffi::c_int {
        loop {
            let pkey = self.pkey.load(std::sync::atomic::Ordering::Relaxed);
            if pkey > 0 {
                return pkey as std::ffi::c_int;
            }

            let mut lg = self.pkey_mut.lock().unwrap();
            if !*lg {
                // No other thread has allocated a pkey between the initial
                // load and us getting the lock:
                let pkey = unsafe {
                    libc_bindings::sys_mman::pkey_alloc(
                        // Reserved flags argument, must be zero:
                        0,
                        // Default permissions set into PKRU for this pkey. Allow all
                        // accesses while in Rust:
                        0,
                    )
                };

                if pkey <= 0 {
                    panic!("Failed to allocate a pkey: {}", pkey);
                }

                self.pkey
                    .store(pkey as usize, std::sync::atomic::Ordering::SeqCst);
                *lg = true;
            }
        }
    }
}

unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for PkeyAlloc<A> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = self.alloc.alloc(layout);

        let res = unsafe {
            libc_bindings::sys_mman::pkey_mprotect(
                ((ptr as usize) & !(4096 - 1)) as *mut std::ffi::c_void,
                layout.size(),
                (libc_bindings::sys_mman::PROT_READ | libc_bindings::sys_mman::PROT_WRITE)
                    as std::ffi::c_int,
                self.get_pkey(),
            )
        };

        if res != 0 {
            panic!("Failed performing pkey_mprotect for alloc()!");
        }

        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        self.alloc.dealloc(ptr, layout)
    }
}
