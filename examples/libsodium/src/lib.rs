use std::ptr::null;

// Necessary evil:
use core::ffi::c_void;
use omniglot::foreign_memory::og_copy::OGCopy;
use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};
use omniglot::rt::OGRuntime;

// Auto-generated bindings, so doesn't follow Rust conventions at all:
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(improper_ctypes)] // TODO: fix this by wrapping functions with u128s
pub mod libsodium_bindings {
    include!(concat!(env!("OUT_DIR"), "/libsodium_bindings.rs"));
}

// These are the Encapsulated Functions wrapper types / traits generated.
use libsodium_bindings::{
    crypto_box_MACBYTES, crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES, crypto_box_SEEDBYTES, crypto_box_easy, crypto_box_open_easy,
    crypto_box_seed_keypair, crypto_generichash, randombytes_SEEDBYTES,
    randombytes_buf_deterministic, sodium_init, LibSodium, LibSodiumRt,
};

//#[global_allocator]
//static GLOBAL_PKEY_ALLOC: omniglot_mpk::PkeyAlloc<std::alloc::System> =
//    omniglot_mpk::PkeyAlloc::new(std::alloc::System);

pub fn libsodium_get_key_pair_unsafe(
    seed: &str,
) -> (
    [u8; crypto_box_PUBLICKEYBYTES as usize],
    [u8; crypto_box_SECRETKEYBYTES as usize],
) {
    let p1_pub_key = [0 as u8; crypto_box_PUBLICKEYBYTES as usize];
    let p1_sec_key = [0 as u8; crypto_box_SECRETKEYBYTES as usize];

    let mut bytes_array = [0; crypto_box_SEEDBYTES as usize];
    let bytes_slice = seed.as_bytes();
    for (i, &byte) in bytes_slice.iter().enumerate() {
        bytes_array[i] = byte;
    }

    unsafe {
        crypto_box_seed_keypair(
            p1_pub_key.as_ptr() as *mut u8,
            p1_sec_key.as_ptr() as *mut u8,
            bytes_array.as_ptr() as *const u8,
        )
    };

    (p1_pub_key, p1_sec_key)
}

pub fn libsodium_get_key_pair<ID: OGID, RT: OGRuntime<ID = ID>, L: LibSodium<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    seed: &str,
) -> (
    [u8; crypto_box_PUBLICKEYBYTES as usize],
    [u8; crypto_box_SECRETKEYBYTES as usize],
) {
    let mut p1_pub_key = [0 as u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut p1_sec_key = [0 as u8; crypto_box_SECRETKEYBYTES as usize];

    let mut bytes_array = [0; crypto_box_SEEDBYTES as usize];
    let bytes_slice = seed.as_bytes();
    for (i, &byte) in bytes_slice.iter().enumerate() {
        bytes_array[i] = byte;
    }

    lib.rt()
        .allocate_stacked_t_mut::<[u8; crypto_box_SEEDBYTES as usize], _, _>(alloc, |seed_ref, alloc|{
            seed_ref.write_copy(&OGCopy::new(bytes_array), access);

            lib.rt()
                .allocate_stacked_t_mut::<[u8; crypto_box_SECRETKEYBYTES as usize], _, _>(alloc, |public_key, alloc| {
                    lib.rt()
                        .allocate_stacked_t_mut::<[u8; crypto_box_PUBLICKEYBYTES as usize], _, _>(alloc, |secret_key, alloc| {
                            lib.crypto_box_seed_keypair(
				public_key.as_ptr() as *mut u8,
				secret_key.as_ptr() as *mut u8,
				seed_ref.as_ptr() as *mut u8,
				alloc,
				access
			    ).unwrap();

                            p1_sec_key = secret_key.copy(access).validate().unwrap();
                        }
                    ).unwrap();
                    p1_pub_key = public_key.copy(access).validate().unwrap();
                }
            ).unwrap();
        }).unwrap();

    (p1_pub_key, p1_sec_key)
}

pub fn libsodium_public_unsafe() {
    // println!();
    // println!("Public key encryption test");

    // println!("Generating Person 1's keys (deterministically)");

    // let mut p1_pub_key = [0 as u8; crypto_box_PUBLICKEYBYTES as usize];
    // let mut p1_sec_key = [0 as u8; crypto_box_SECRETKEYBYTES as usize];

    // Get a key pair for both person 1 and person 2
    let (p1_pub_key, p1_sec_key) = libsodium_get_key_pair_unsafe("Person 1 Seed");

    // println!("Person 1 Public key: {:2x?}", p1_pub_key);
    // println!("Person 1 Secret key: {:2x?}", p1_sec_key);

    // println!("Generating Person 2's keys (deterministically)");

    let (p2_pub_key, p2_sec_key) = libsodium_get_key_pair_unsafe("Person 2 Seed");

    // println!("Person 2 Public key: {:2x?}", p2_pub_key);
    // println!("Person 2 Secret key: {:2x?}", p2_sec_key);

    // Get a random nonce

    let rand_seed = "Nonce seed";

    let mut bytes_array = [0; randombytes_SEEDBYTES as usize];
    let bytes_slice = rand_seed.as_bytes();
    for (i, &byte) in bytes_slice.iter().enumerate() {
        bytes_array[i] = byte;
    }

    // // println!("Rand seed bytes {:2x?}", &OGCopy::new(rand_seed_bytes).validate().unwrap());

    let nonce = [0 as u8; crypto_box_NONCEBYTES as usize];
    unsafe {
        randombytes_buf_deterministic(
            nonce.as_ptr() as *mut c_void,
            crypto_box_NONCEBYTES as usize,
            bytes_array.as_ptr() as *const u8,
        )
    };

    // TODO WHY ISN'T THIS DETERMINISTIC
    // println!("Nonce: {:2x?}", nonce);

    // For now to reintroduce deterministicness
    let nonce = [42 as u8; crypto_box_NONCEBYTES as usize];

    // Create encrypted message

    const M_TO_SEND: &str = "Message to encrypt!";
    let mut m_to_send = [0 as u8; M_TO_SEND.len() as usize];
    m_to_send[..M_TO_SEND.len()].copy_from_slice(M_TO_SEND.as_bytes());

    const CIPHERTEXT_LEN: usize = crypto_box_MACBYTES as usize + M_TO_SEND.len() as usize;

    let cipher = [0 as u8; CIPHERTEXT_LEN];

    unsafe {
        crypto_box_easy(
            cipher.as_ptr() as *mut u8,
            m_to_send.as_ptr() as *const u8,
            M_TO_SEND.len() as u64,
            nonce.as_ptr() as *const u8,
            p2_pub_key.as_ptr() as *const u8,
            p1_sec_key.as_ptr() as *const u8,
        );
    }

    // println!("Cipher: {:2x?}", cipher);

    // Decrypt
    let decrypted = [0; M_TO_SEND.len()];
    unsafe {
        crypto_box_open_easy(
            decrypted.as_ptr() as *mut u8,
            cipher.as_ptr() as *const u8,
            CIPHERTEXT_LEN as u64,
            nonce.as_ptr() as *const u8,
            p1_pub_key.as_ptr() as *const u8,
            p2_sec_key.as_ptr() as *const u8,
        );
    }

    let _s = String::from_utf8((&decrypted).to_vec()).expect("Decrypt");
    // println!("Decrypted: {}", s);
}

pub fn libsodium_public<ID: OGID, RT: OGRuntime<ID = ID>, L: LibSodium<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    // println!();
    // println!("Public key encryption test");

    // println!("Generating Person 1's keys (deterministically)");

    // let mut p1_pub_key = [0 as u8; crypto_box_PUBLICKEYBYTES as usize];
    // let mut p1_sec_key = [0 as u8; crypto_box_SECRETKEYBYTES as usize];

    // Get a key pair for both person 1 and person 2
    let (p1_pub_key, p1_sec_key) = libsodium_get_key_pair(lib, alloc, access, "Person 1 Seed");

    // println!("Person 1 Public key: {:2x?}", p1_pub_key);
    // println!("Person 1 Secret key: {:2x?}", p1_sec_key);

    // println!("Generating Person 2's keys (deterministically)");

    let (p2_pub_key, p2_sec_key) = libsodium_get_key_pair(lib, alloc, access, "Person 2 Seed");

    // println!("Person 2 Public key: {:2x?}", p2_pub_key);
    // println!("Person 2 Secret key: {:2x?}", p2_sec_key);

    // Get a random nonce

    let rand_seed = "Nonce seed";

    let mut bytes_array = [0; randombytes_SEEDBYTES as usize];
    let bytes_slice = rand_seed.as_bytes();
    for (i, &byte) in bytes_slice.iter().enumerate() {
        bytes_array[i] = byte;
    }

    // // println!("Rand seed bytes {:2x?}", &OGCopy::new(rand_seed_bytes).validate().unwrap());

    let _nonce = lib
        .rt()
        .allocate_stacked_t_mut::<[u8; randombytes_SEEDBYTES as usize], _, _>(
            alloc,
            |seed_ref, alloc| {
                seed_ref.write_copy(&OGCopy::new(bytes_array), access);

                lib.rt()
                    .allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(
                        alloc,
                        |nonce_gen, alloc| {
                            nonce_gen.write([0 as u8; crypto_box_NONCEBYTES as usize], access);

                            lib.randombytes_buf_deterministic(
                                nonce_gen.as_ptr() as *mut c_void,
                                crypto_box_NONCEBYTES as usize,
                                seed_ref.as_ptr() as *mut u8,
                                alloc,
                                access,
                            )
                            .unwrap();

                            nonce_gen.copy(access).validate().unwrap()
                        },
                    )
                    .unwrap()
            },
        )
        .unwrap();

    // TODO WHY ISN'T THIS DETERMINISTIC
    // println!("Nonce: {:2x?}", nonce);

    // For now to reintroduce deterministicness
    let nonce = [42; crypto_box_NONCEBYTES as usize];

    // Create encrypted message

    const M_TO_SEND: &str = "Message to encrypt!";
    let mut m_to_send = [0 as u8; M_TO_SEND.len() as usize];
    m_to_send[..M_TO_SEND.len()].copy_from_slice(M_TO_SEND.as_bytes());

    const CIPHERTEXT_LEN: usize = crypto_box_MACBYTES as usize + M_TO_SEND.len() as usize;

    let cipher =
    lib.rt().allocate_stacked_t_mut::<[u8; M_TO_SEND.len() as usize], _, _>(alloc, |message_to_send, alloc| {
            message_to_send.write_copy(&OGCopy::new(m_to_send), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(alloc, |nonce_to_send, alloc| {
        nonce_to_send.write_copy(&OGCopy::new(nonce), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_PUBLICKEYBYTES as usize], _, _>(alloc, |pub_key_to_send, alloc| {
                pub_key_to_send.write_copy(&OGCopy::new(p2_pub_key), access);

                lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_SECRETKEYBYTES as usize], _, _>(alloc, |sec_key_to_send, alloc| {
                    sec_key_to_send.write_copy(&OGCopy::new(p1_sec_key), access);

                    lib.rt().allocate_stacked_t_mut::<[u8; CIPHERTEXT_LEN as usize], _, _>(alloc, |cipher, alloc| {
                        cipher.write([0;CIPHERTEXT_LEN], access);

                        let res = lib.crypto_box_easy(
                cipher.as_ptr().cast::<u8>().into(),
                message_to_send.as_ptr() as *mut u8,
                            M_TO_SEND.len() as u64,
                nonce_to_send.as_ptr() as *mut u8,
                pub_key_to_send.as_ptr() as *mut u8,
			    sec_key_to_send.as_ptr() as *mut u8,
			    alloc,
                            access,
                        ).unwrap();

                        assert!(res.validate().unwrap() == 0);


                        cipher.copy(access).validate().unwrap()
                    }).unwrap()
                }).unwrap()
            }).unwrap()
        }).unwrap()
    }).unwrap();

    // println!("Cipher: {:2x?}", cipher);

    // Decrypt

    let _decrypted =
	lib.rt().allocate_stacked_t_mut::<[u8; CIPHERTEXT_LEN as usize], _, _>(alloc, |cipher_to_send, alloc| {
            cipher_to_send.write_copy(&OGCopy::new(cipher), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(alloc, |nonce_to_send, alloc| {
		nonce_to_send.write_copy(&OGCopy::new(nonce), access);

		lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_PUBLICKEYBYTES as usize], _, _>(alloc, |pub_key_to_send, alloc| {
                    pub_key_to_send.write_copy(&OGCopy::new(p1_pub_key), access);

                    lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_SECRETKEYBYTES as usize], _, _>(alloc, |sec_key_to_send, alloc| {
			sec_key_to_send.write_copy(&OGCopy::new(p2_sec_key), access);

			lib.rt().allocate_stacked_t_mut::<[u8; M_TO_SEND.len() as usize], _, _>(alloc, |decrypted, alloc| {
                            decrypted.write([0;M_TO_SEND.len()], access);

                            let res = lib.crypto_box_open_easy(
				decrypted.as_ptr() as *mut u8,
				cipher_to_send.as_ptr() as *mut u8,
				CIPHERTEXT_LEN as u64,
				nonce_to_send.as_ptr() as *mut u8,
				pub_key_to_send.as_ptr() as *mut u8,
				sec_key_to_send.as_ptr() as *mut u8,
				alloc,
				access
                            ).unwrap();

                            assert!(res.validate().unwrap() == 0);

                            // decrypted.copy(access).validate().unwrap()

                            // core::hint::black_box(
                            //     &*decrypted
                            //         .as_immut()
                            //         .as_slice()
                            //         .validate_as_str(access)
                            //         .unwrap(),
                            // );

			}).unwrap()
                    }).unwrap()
		}).unwrap()
            }).unwrap()
	}).unwrap();

    // let s = String::from_utf8((&decrypted).to_vec()).expect("Decrypt");
    // println!("Decrypted: {}", s);
}

pub fn libsodium_public_validate<
    ID: OGID,
    RT: OGRuntime<ID = ID>,
    L: LibSodium<ID, RT, RT = RT>,
>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    // println!();
    // println!("Public key encryption test");

    // println!("Generating Person 1's keys (deterministically)");

    // let mut p1_pub_key = [0 as u8; crypto_box_PUBLICKEYBYTES as usize];
    // let mut p1_sec_key = [0 as u8; crypto_box_SECRETKEYBYTES as usize];

    // Get a key pair for both person 1 and person 2
    let (p1_pub_key, p1_sec_key) = libsodium_get_key_pair(lib, alloc, access, "Person 1 Seed");

    // println!("Person 1 Public key: {:2x?}", p1_pub_key);
    // println!("Person 1 Secret key: {:2x?}", p1_sec_key);

    // println!("Generating Person 2's keys (deterministically)");

    let (p2_pub_key, p2_sec_key) = libsodium_get_key_pair(lib, alloc, access, "Person 2 Seed");

    // println!("Person 2 Public key: {:2x?}", p2_pub_key);
    // println!("Person 2 Secret key: {:2x?}", p2_sec_key);

    // Get a random nonce

    let rand_seed = "Nonce seed";

    let mut bytes_array = [0; randombytes_SEEDBYTES as usize];
    let bytes_slice = rand_seed.as_bytes();
    for (i, &byte) in bytes_slice.iter().enumerate() {
        bytes_array[i] = byte;
    }

    // // println!("Rand seed bytes {:2x?}", &OGCopy::new(rand_seed_bytes).validate().unwrap());

    let _nonce = lib
        .rt()
        .allocate_stacked_t_mut::<[u8; randombytes_SEEDBYTES as usize], _, _>(
            alloc,
            |seed_ref, alloc| {
                seed_ref.write_copy(&OGCopy::new(bytes_array), access);

                lib.rt()
                    .allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(
                        alloc,
                        |nonce_gen, alloc| {
                            nonce_gen.write([0 as u8; crypto_box_NONCEBYTES as usize], access);

                            lib.randombytes_buf_deterministic(
                                nonce_gen.as_ptr() as *mut c_void,
                                crypto_box_NONCEBYTES as usize,
                                seed_ref.as_ptr() as *mut u8,
                                alloc,
                                access,
                            )
                            .unwrap();

                            nonce_gen.copy(access).validate().unwrap()
                        },
                    )
                    .unwrap()
            },
        )
        .unwrap();

    // TODO WHY ISN'T THIS DETERMINISTIC
    // println!("Nonce: {:2x?}", nonce);

    // For now to reintroduce deterministicness
    let nonce = [42; crypto_box_NONCEBYTES as usize];

    // Create encrypted message

    const M_TO_SEND: &str = "Message to encrypt!";
    let mut m_to_send = [0 as u8; M_TO_SEND.len() as usize];
    m_to_send[..M_TO_SEND.len()].copy_from_slice(M_TO_SEND.as_bytes());

    const CIPHERTEXT_LEN: usize = crypto_box_MACBYTES as usize + M_TO_SEND.len() as usize;

    let cipher =
    lib.rt().allocate_stacked_t_mut::<[u8; M_TO_SEND.len() as usize], _, _>(alloc, |message_to_send, alloc| {
            message_to_send.write_copy(&OGCopy::new(m_to_send), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(alloc, |nonce_to_send, alloc| {
        nonce_to_send.write_copy(&OGCopy::new(nonce), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_PUBLICKEYBYTES as usize], _, _>(alloc, |pub_key_to_send, alloc| {
                pub_key_to_send.write_copy(&OGCopy::new(p2_pub_key), access);

                lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_SECRETKEYBYTES as usize], _, _>(alloc, |sec_key_to_send, alloc| {
                    sec_key_to_send.write_copy(&OGCopy::new(p1_sec_key), access);

                    lib.rt().allocate_stacked_t_mut::<[u8; CIPHERTEXT_LEN as usize], _, _>(alloc, |cipher, alloc| {
                        cipher.write([0;CIPHERTEXT_LEN], access);

                        let res = lib.crypto_box_easy(
                cipher.as_ptr() as *mut u8,
                message_to_send.as_ptr() as *mut u8,
                            M_TO_SEND.len() as u64,
                nonce_to_send.as_ptr() as *mut u8,
                pub_key_to_send.as_ptr() as *mut u8,
			    sec_key_to_send.as_ptr() as *mut u8,
			    alloc,
                            access,
                        ).unwrap();

                        assert!(res.validate().unwrap() == 0);


                        cipher.copy(access).validate().unwrap()
                    }).unwrap()
                }).unwrap()
            }).unwrap()
        }).unwrap()
    }).unwrap();

    // println!("Cipher: {:2x?}", cipher);

    // Decrypt

    let _decrypted =
	lib.rt().allocate_stacked_t_mut::<[u8; CIPHERTEXT_LEN as usize], _, _>(alloc, |cipher_to_send, alloc| {
            cipher_to_send.write_copy(&OGCopy::new(cipher), access);

            lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_NONCEBYTES as usize], _, _>(alloc, |nonce_to_send, alloc| {
		nonce_to_send.write_copy(&OGCopy::new(nonce), access);

		lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_PUBLICKEYBYTES as usize], _, _>(alloc, |pub_key_to_send, alloc| {
                    pub_key_to_send.write_copy(&OGCopy::new(p1_pub_key), access);

                    lib.rt().allocate_stacked_t_mut::<[u8; crypto_box_SECRETKEYBYTES as usize], _, _>(alloc, |sec_key_to_send, alloc| {
			sec_key_to_send.write_copy(&OGCopy::new(p2_sec_key), access);

			lib.rt().allocate_stacked_t_mut::<[u8; M_TO_SEND.len() as usize], _, _>(alloc, |decrypted, alloc| {
                            decrypted.write([0;M_TO_SEND.len()], access);

                            let res = lib.crypto_box_open_easy(
				decrypted.as_ptr() as *mut u8,
				cipher_to_send.as_ptr() as *mut u8,
				CIPHERTEXT_LEN as u64,
				nonce_to_send.as_ptr() as *mut u8,
				pub_key_to_send.as_ptr() as *mut u8,
				sec_key_to_send.as_ptr() as *mut u8,
				alloc,
				access
                            ).unwrap();

                            assert!(res.validate().unwrap() == 0);

                            // decrypted.copy(access).validate().unwrap()

                            core::hint::black_box(
                                &*decrypted
                                    .as_immut()
                                    .as_slice()
                                    .validate_as_str(access)
                                    .unwrap(),
                            );

			}).unwrap()
                    }).unwrap()
		}).unwrap()
            }).unwrap()
	}).unwrap();

    // let s = String::from_utf8((&decrypted).to_vec()).expect("Decrypt");
    // println!("Decrypted: {}", s);
}

pub fn libsodium_hash_unsafe(message: &[u8]) -> [u8; 32] {
    let hash = [0 as u8; 32];
    let res = unsafe {
        crypto_generichash(
            hash.as_ptr() as *mut u8,
            32,
            message.as_ptr() as *const u8,
            message.len() as u64,
            null(),
            0,
        )
    };

    assert!(res == 0);

    hash
}

// The signature of this is quite ugly. Unfortunately I haven't found a way to
// make it nicer without things breaking:
pub fn libsodium_hash_og<ID: OGID, RT: OGRuntime<ID = ID>, L: LibSodium<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    message: &[u8],
    result_cb: impl FnOnce(&[u8]),
) {
    lib.rt()
        .allocate_stacked_slice_mut::<u8, _, _>(message.len(), alloc, |message_ref, alloc| {
            // Initialize the EFAllocation into an EFMutVal:
            message_ref.copy_from_slice(message, access);

            lib.rt()
                .allocate_stacked_t_mut::<[u8; 32], _, _>(alloc, |hash_ref, alloc| {
                    let res = lib
                        .crypto_generichash(
                            hash_ref.as_ptr().cast::<u8>().into(),
                            32,
                            message_ref.as_ptr(),
                            message.len() as u64,
                            null(),
                            0,
                            alloc,
                            access,
                        )
                        .unwrap()
                        .validate()
                        .unwrap();

                    assert!(res == 0);

                    result_cb(&*hash_ref.validate(&access).unwrap())
                })
                .unwrap();
        })
        .unwrap();
}

pub fn calc_hash<ID: OGID, RT: OGRuntime<ID = ID>, L: LibSodium<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    lib.rt()
        .allocate_stacked_t_mut::<[u8; 4096], _, _>(alloc, |message, alloc| {
            // Initialize the EFAllocation into an EFMutVal:
            message.write([42; 4096], access);

            lib.rt()
                .allocate_stacked_t_mut::<[u8; 32], _, _>(alloc, |hash, alloc| {
                    let res = lib
                        .crypto_generichash(
                            hash.as_ptr() as *mut u8,
                            32,
                            message.as_ptr() as *const u8,
                            4096,
                            null(),
                            0,
                            alloc,
                            access,
                        )
                        .unwrap();
                    assert!(res.validate().unwrap() == 0);
                })
                .unwrap();
        })
        .unwrap();
}

pub fn calc_hash_validate<ID: OGID, RT: OGRuntime<ID = ID>, L: LibSodium<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    lib.rt()
        .allocate_stacked_t_mut::<[u8; 4096], _, _>(alloc, |message, alloc| {
            // Initialize the EFAllocation into an EFMutVal:
            message.write([42; 4096], access);

            lib.rt()
                .allocate_stacked_t_mut::<[u8; 32], _, _>(alloc, |hash, alloc| {
                    let res = lib
                        .crypto_generichash(
                            hash.as_ptr() as *mut u8,
                            32,
                            message.as_ptr() as *const u8,
                            4096,
                            null(),
                            0,
                            alloc,
                            access,
                        )
                        .unwrap();
                    core::hint::black_box(&*hash.validate(access).unwrap());
                    assert!(res.validate().unwrap() == 0);
                })
                .unwrap();
        })
        .unwrap();
}

pub fn calc_hash_unsafe() {
    let message = [42 as u8; 4096];

    let hash = [0 as u8; 32];
    unsafe {
        crypto_generichash(
            hash.as_ptr() as *mut u8,
            32,
            message.as_ptr() as *const u8,
            message.len() as u64,
            null(),
            0,
        )
    };
}

pub fn with_mockrt_lib<'a, ID: OGID + 'a, A: omniglot::rt::mock::MockRtAllocator, R>(
    brand: ID,
    allocator: A,
    f: impl FnOnce(
        LibSodiumRt<ID, omniglot::rt::mock::MockRt<ID, A>, omniglot::rt::mock::MockRt<ID, A>>,
        AllocScope<
            <omniglot::rt::mock::MockRt<ID, A> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    // This is unsafe, as it instantiates a runtime that can be used to run
    // foreign functions without memory protection:
    let (rt, alloc, access) =
        unsafe { omniglot::rt::mock::MockRt::new(false, false, allocator, brand) };

    // Create a "bound" runtime, which implements the LibSodium API:
    let bound_rt = LibSodiumRt::new(rt).unwrap();

    // All further functions expect libsodium to be initialized:
    // println!("Initializing libsodium...");
    // assert!(
    //     0 == bound_rt
    //         .sodium_init(&mut access)
    //         .unwrap()
    //         .validate()
    //         .unwrap()
    // );
    // println!("Libsodium initialized!");

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_mpkrt_lib<ID: OGID, R>(
    brand: ID,
    f: impl for<'a> FnOnce(
        LibSodiumRt<ID, omniglot_mpk::OGMPKRuntime<ID>, omniglot_mpk::OGMPKRuntime<ID>>,
        AllocScope<
            <omniglot_mpk::OGMPKRuntime<ID> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    let (rt, mut alloc, mut access) = omniglot_mpk::OGMPKRuntime::new(
        [c"libsodium.so"].into_iter(),
        brand,
        //Some(GLOBAL_PKEY_ALLOC.get_pkey()),
        None,
        false,
    );

    // Create a "bound" runtime, which implements the LibSodium API:
    let bound_rt = LibSodiumRt::new(rt).unwrap();

    // All further functions expect libsodium to be initialized:
    // println!("Initializing libsodium:");
    assert!(
        0 == bound_rt
            .sodium_init(&mut alloc, &mut access)
            .unwrap()
            .validate()
            .unwrap()
    );
    // println!("Libsodium initialized!");

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_no_lib(f: impl FnOnce()) {
    // println!("Initializing libsodium:");
    unsafe { sodium_init() };
    // println!("Libsodium initialized!");

    f();
}
