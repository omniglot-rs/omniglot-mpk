use brotli::*;
use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};
use omniglot::rt::OGRuntime;

// Auto-generated bindings, so doesn't follow Rust conventions at all:
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod brotli {
    include!(concat!(env!("OUT_DIR"), "/brotli_bindings.rs"));
}

const MESSAGE: &str = "As the Manager of the Performance sits before the curtain on the boards, \
     and looks into the Fair, a feeling of profound melancholy comes over him \
     in his survey of the bustling place. There is a great quantity of eating \
     and drinking, making love and jilting, laughing and the contrary, \
     smoking, cheating, fighting, dancing, and fiddling: there are bullies \
     pushing about, bucks ogling the women, knaves picking pockets, policemen \
     on the look-out, quacks (other quacks, plague take them!) bawling in \
     front of their booths, and yokels looking up at the tinselled dancers \
     and poor old rouged tumblers, while the light-fingered folk are operating \
     upon their pockets behind. Yes, this is Vanity Fair; not a moral place \
     certainly; nor a merry one, though very noisy. Look at the faces of the \
     actors and buffoons when they come off from their business; and Tom Fool \
     washing the paint off his cheeks before he sits down to dinner with his \
     wife and the little Jack Puddings behind the canvass. The curtain will be \
     up presently, and he will be turning head over heels, and crying, 'How \
     are you?' \
     A man with a reflective turn of mind, walking through an exhibition of \
     this sort, will not be oppressed, I take it, by his own or other people's \
     hilarity. An episode of humour or kindness touches and amuses him here \
     and there;—a pretty child looking at a gingerbread stall; a pretty girl \
     blushing whilst her lover talks to her and chooses her fairing; poor Tom \
     Fool, yonder behind the waggon, mumbling his bone with the honest family \
     which lives by his tumbling;—but the general impression is one more \
     melancholy than mirthful. When you come home you sit down, in a sober, \
     contemplative, not uncharitable frame of mind, and apply yourself to your \
     books or your business. \
     I have no other moral than this to tag to the present story of 'Vanity \
     Fair'. Some people consider Fairs immoral altogether, and eschew such, \
     with their servants and families: very likely they are right. But persons \
     who think otherwise and are of a lazy, or a benevolent, or a sarcastic \
     mood, may perhaps like to step in for half an hour and look at the \
     performances. There are scenes of all sorts; some dreadful combats, some \
     grand and lofty horse-riding, some scenes of high life, and some of very \
     middling indeed; some love-making for the sentimental, and some light \
     comic business: the whole accompanied by appropriate scenery, and \
     brilliantly illuminated with the Author's own candles. \
     What more has the Manager of the Performance to say?—To acknowledge the \
     kindness with which it has been received in all the principal towns of \
     England through which the Show has passed, and where it has been most \
     favourably noticed by the respected conductors of the Public Press, and \
     by the Nobility and Gentry. He is proud to think that his Puppets have \
     given satisfaction to the very best company in this empire. The famous \
     little Becky Puppet has been pronounced to be uncommonly flexible in the \
     joints and lively on the wire: the Amelia Doll, though it has had a \
     smaller circle of admirers, has yet been carved and dressed with the \
     greatest care by the artist: the Dobbin Figure, though apparently clumsy, \
     yet dances in a very amusing and natural manner: the Little Boys' Dance \
     has been liked by some; and please to remark the richly dressed figure of \
     the Wicked Nobleman, on which no expense has been spared, and which Old \
     Nick will fetch away at the end of this singular performance. \
     And with this, and a profound bow to his patrons, the Manager retires, \
     and the curtain rises.";

pub fn test_brotli<ID: OGID, RT: OGRuntime<ID = ID>, L: Brotli<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    message_len: usize,
) {
    // Take a nicer, power-of-two number of the first characters to compress:
    let message_to_compress = MESSAGE.get(..message_len).unwrap();

    // Allocate a compressed buffer with twice the message size. This
    // should hopefully be sufficient even for entirely random messages,
    // with any headers that are attached:
    let encoded_buf_size = message_to_compress.as_bytes().len() * 2;

    lib.rt()
        .allocate_stacked_slice_mut::<u8, _, _>(encoded_buf_size, alloc, |encoded_buf, alloc| {
            let encoded_size = lib
                .rt()
                .allocate_stacked_t_mut::<usize, _, _>(alloc, |encoded_size_ref, alloc| {
                    // Before compression, the encoded size pointer argument
                    // needs to contain the available buffer space:
                    encoded_size_ref.write(encoded_buf_size, access);

                    // Copy the message into foreign memory:
                    lib.rt()
                        .allocate_stacked_slice_mut::<u8, _, _>(
                            message_to_compress.as_bytes().len(),
                            alloc,
                            |source_buf, alloc| {
                                source_buf.copy_from_slice(message_to_compress.as_bytes(), access);

                                // This will make the string invalid UTF-8, causing the below
                                // validation to fail:
                                //message_ref.write_from_iter(core::iter::repeat(0xFF), access);

                                assert_eq!(
                                    1,
                                    lib.BrotliEncoderCompress(
                                        brotli::BROTLI_DEFAULT_QUALITY as i32,
                                        brotli::BROTLI_DEFAULT_WINDOW as i32,
                                        brotli::BrotliEncoderMode_BROTLI_MODE_GENERIC,
                                        message_to_compress.as_bytes().len(),
                                        source_buf.as_ptr(),
                                        encoded_size_ref.as_ptr().into(),
                                        encoded_buf.as_ptr(),
                                        alloc,
                                        access,
                                    )
                                    .unwrap()
                                    .validate()
                                    .unwrap()
                                );
                            },
                        )
                        .unwrap();

                    // Return the encoded size:
                    *encoded_size_ref.validate(access).unwrap()
                })
                .unwrap();

            // Allocate a buffer for the decoded text, with the same length as the original message.
            lib.rt()
                .allocate_stacked_slice_mut::<u8, _, _>(
                    message_to_compress.as_bytes().len(),
                    alloc,
                    |decoded_buf, alloc| {
                        // Allocate a field to store the decoded size in. It
                        // should be set to the initial available buffer
                        // space:
                        lib.rt()
                            .allocate_stacked_t_mut::<usize, _, _>(
                                alloc,
                                |decoded_size_ref, alloc| {
                                    decoded_size_ref
                                        .write(message_to_compress.as_bytes().len(), access);

                                    assert_eq!(
                                        brotli::BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS,
                                        lib.BrotliDecoderDecompress(
                                            encoded_size,
                                            encoded_buf.as_ptr(),
                                            decoded_size_ref.as_ptr().into(),
                                            decoded_buf.as_ptr().into(),
                                            alloc,
                                            access
                                        )
                                        .unwrap()
                                        .validate()
                                        .unwrap(),
                                    );
                                },
                            )
                            .unwrap();

                        // Compare the encoded & decoded message:
                        assert_eq!(
                            message_to_compress,
                            &*decoded_buf.as_immut().validate_as_str(access).unwrap(),
                        );
                    },
                )
                .unwrap();
        })
        .unwrap();
}

pub unsafe fn test_brotli_unsafe(message_len: usize) {
    // Take a nicer, power-of-two number of the first characters to compress:
    let message_to_compress = MESSAGE.get(..message_len).unwrap();

    // Allocate a compressed buffer with twice the maximum message
    // size. This should hopefully be sufficient even for entirely
    // random messages, with any headers that are attached:
    let mut encoded_buf = [0; MESSAGE.len() * 2];

    // Allocate a buffer for the decompressed output:
    let mut decoded_buf = [0; MESSAGE.len()];

    // Before compression, the encoded size pointer argument needs to
    // contain the available buffer space:
    let mut encoded_size: usize = encoded_buf.len();

    assert_eq!(1, unsafe {
        brotli::BrotliEncoderCompress(
            brotli::BROTLI_DEFAULT_QUALITY as i32,
            brotli::BROTLI_DEFAULT_WINDOW as i32,
            brotli::BrotliEncoderMode_BROTLI_MODE_GENERIC,
            message_to_compress.as_bytes().len(),
            message_to_compress.as_bytes().as_ptr(),
            &mut encoded_size as *mut _,
            encoded_buf.as_mut_ptr(),
        )
    },);

    // Before decompression, the decoded size pointer argument needs
    // to contain the available buffer space:
    let mut decoded_size = decoded_buf.len();

    assert_eq!(
        brotli::BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS,
        unsafe {
            brotli::BrotliDecoderDecompress(
                encoded_size,
                encoded_buf.as_ptr(),
                &mut decoded_size as *mut _,
                decoded_buf.as_mut_ptr(),
            )
        },
    );

    // Compare the encoded & decoded message:
    assert_eq!(message_to_compress, unsafe {
        std::str::from_utf8_unchecked(&decoded_buf[..decoded_size])
    },);
}

pub fn with_mockrt_lib<'a, ID: OGID + 'a, A: omniglot::rt::mock::MockRtAllocator, R>(
    brand: ID,
    allocator: A,
    f: impl FnOnce(
        BrotliRt<ID, omniglot::rt::mock::MockRt<ID, A>, omniglot::rt::mock::MockRt<ID, A>>,
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

    // Create a "bound" runtime, which implements the Brotli API:
    let bound_rt = BrotliRt::new(rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_mpkrt_lib<ID: OGID, R>(
    brand: ID,
    f: impl for<'a> FnOnce(
        BrotliRt<ID, omniglot_mpk::OGMPKRuntime<ID>, omniglot_mpk::OGMPKRuntime<ID>>,
        AllocScope<
            <omniglot_mpk::OGMPKRuntime<ID> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    let (rt, alloc, access) = omniglot_mpk::OGMPKRuntime::new(
        [
            c"libbrotlienc.so",
            c"libbrotlidec.so",
            c"libbrotlicommon.so",
        ]
        .into_iter(),
        brand,
        //Some(GLOBAL_PKEY_ALLOC.get_pkey()),
        None,
        true,
    );

    // Create a "bound" runtime, which implements the Brotli API:
    let bound_rt = BrotliRt::new(rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_no_lib(f: impl FnOnce()) {
    f();
}
