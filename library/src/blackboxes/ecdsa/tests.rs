use super::{
    constants::{SECP256K1_N, SECP256R1_N},
    curve::{Curve, Secp256k1},
    modular::{
        append_inv_mod_n_barrett, append_mul_mod_n_barrett, append_mul_mod_p_secp256k1,
        emit_secp256k1_inv_mod_p_helper, emit_secp256k1_mul_mod_n_helper,
        emit_secp256k1_mul_mod_p_helper, emit_secp256r1_mul_mod_n_helper,
    },
    point::{append_joint_scalar_mul, append_point_add_mixed_complete},
};
use crate::{
    blackboxes::common::{block_args, felt_type},
    multiprec::LIMBS,
};
use acir::AcirField;
use llzk::prelude::{
    Block, BlockLike, FuncDefOpLike, FunctionType, LlzkContext, Location, Module, OperationLike,
    RegionLike, Value, WalkOrder, WalkResult, dialect, llzk_module,
};
use llzk_interpreter::{Felt, Interpreter, Value as InterpValue};
use num_bigint::BigUint;

fn build_test_module<'c>(context: &'c LlzkContext) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    let felt_ty = felt_type(context);
    let input_types = vec![felt_ty; 2 * LIMBS];
    let output_types = vec![felt_ty; LIMBS];
    let inputs = vec![(felt_ty, location); 2 * LIMBS];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, "test_mul_mod_p_k1", function_type, &[], None)
        .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let lhs: [Value; LIMBS] = block_args::<LIMBS>(&block, 0).expect("block args");
    let rhs: [Value; LIMBS] = block_args::<LIMBS>(&block, LIMBS).expect("block args");
    let result =
        append_mul_mod_p_secp256k1(&block, context, location, &lhs, &rhs).expect("mul_mod_p");
    block.append_operation(dialect::function::r#return(location, &result));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());

    module
}

fn limbs_of(value: &BigUint) -> [InterpValue; LIMBS] {
    let mask = (BigUint::from(1u128) << 64) - 1u32;
    std::array::from_fn(|i| {
        let limb = (value >> (64 * i)) & &mask;
        InterpValue::Felt(Felt::new(limb))
    })
}

fn run_mul(a: &BigUint, b: &BigUint) -> BigUint {
    let context = LlzkContext::new();
    let module = build_test_module(&context);
    assert!(module.as_operation().verify(), "module should verify");

    let mut args = Vec::with_capacity(2 * LIMBS);
    args.extend(limbs_of(a));
    args.extend(limbs_of(b));

    let mut interp = Interpreter::new(&module);
    let result_values = interp
        .run_function("@test_mul_mod_p_k1", &args)
        .expect("run");

    let mut result = BigUint::from(0u32);
    for (i, v) in result_values.iter().enumerate() {
        let InterpValue::Felt(f) = v else {
            panic!("expected felt result")
        };
        result += f.as_biguint() << (64 * i);
    }
    result
}

fn p_k1() -> BigUint {
    (BigUint::from(1u128) << 256) - (BigUint::from(1u128) << 32) - BigUint::from(977u32)
}

#[test]
fn one_times_one_is_one() {
    let one = BigUint::from(1u32);
    assert_eq!(run_mul(&one, &one), one);
}

#[test]
fn zero_times_anything_is_zero() {
    let zero = BigUint::from(0u32);
    let big = BigUint::from(0xdeadbeefu64);
    assert_eq!(run_mul(&zero, &big), zero);
    assert_eq!(run_mul(&big, &zero), zero);
}

#[test]
fn small_mul_no_reduction() {
    let a = BigUint::from(3u32);
    let b = BigUint::from(5u32);
    assert_eq!(run_mul(&a, &b), BigUint::from(15u32));
}

#[test]
fn p_minus_one_squared_is_one() {
    let p = p_k1();
    let pm1 = &p - 1u32;
    let one = BigUint::from(1u32);
    assert_eq!(run_mul(&pm1, &pm1), one);
}

#[test]
fn large_values_match_native_mod() {
    let a = BigUint::parse_bytes(
        b"BAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00D",
        16,
    )
    .unwrap();
    let b = BigUint::parse_bytes(
        b"DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA98765432100123456789ABCDEF",
        16,
    )
    .unwrap();
    let p = p_k1();
    let expected = (&a * &b) % &p;
    assert_eq!(run_mul(&a, &b), expected);
}

// ── mul_mod_n via Barrett ────────────────────────────────────────────

/// secp256k1 scalar field modulus.
fn n_k1() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

fn limbs_from_big(value: &BigUint) -> [u64; LIMBS] {
    let mask = BigUint::from(u64::MAX);
    std::array::from_fn(|i| {
        let limb = (value >> (64 * i)) & &mask;
        u64::try_from(limb).expect("64-bit limb")
    })
}

fn build_test_module_barrett<'c>(context: &'c LlzkContext, n_limbs: [u64; LIMBS]) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    let felt_ty = felt_type(context);
    let input_types = vec![felt_ty; 2 * LIMBS];
    let output_types = vec![felt_ty; LIMBS];
    let inputs = vec![(felt_ty, location); 2 * LIMBS];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, "test_mul_mod_n", function_type, &[], None)
        .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let lhs: [Value; LIMBS] = block_args::<LIMBS>(&block, 0).expect("block args");
    let rhs: [Value; LIMBS] = block_args::<LIMBS>(&block, LIMBS).expect("block args");
    let result = append_mul_mod_n_barrett(&block, context, location, &lhs, &rhs, &n_limbs)
        .expect("mul_mod_n");
    block.append_operation(dialect::function::r#return(location, &result));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());
    module
}

fn run_mul_mod_n(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let n_limbs = limbs_from_big(n);
    let context = LlzkContext::new();
    let module = build_test_module_barrett(&context, n_limbs);
    assert!(module.as_operation().verify(), "module should verify");
    let mut args = Vec::with_capacity(2 * LIMBS);
    args.extend(limbs_of(a));
    args.extend(limbs_of(b));
    let mut interp = Interpreter::new(&module);
    let out = interp.run_function("@test_mul_mod_n", &args).expect("run");
    let mut acc = BigUint::from(0u32);
    for (i, v) in out.iter().enumerate() {
        let InterpValue::Felt(f) = v else {
            panic!("expected felt")
        };
        acc += f.as_biguint() << (64 * i);
    }
    acc
}

#[test]
fn barrett_one_times_one_n_k1() {
    let n = n_k1();
    let one = BigUint::from(1u32);
    assert_eq!(run_mul_mod_n(&one, &one, &n), one);
}

#[test]
fn barrett_zero_times_x_n_k1() {
    let n = n_k1();
    let zero = BigUint::from(0u32);
    let x = BigUint::from(0xdeadbeefu64);
    assert_eq!(run_mul_mod_n(&zero, &x, &n), zero);
}

#[test]
fn barrett_small_no_reduction_n_k1() {
    let n = n_k1();
    let a = BigUint::from(7u32);
    let b = BigUint::from(11u32);
    assert_eq!(run_mul_mod_n(&a, &b, &n), BigUint::from(77u32));
}

#[test]
fn barrett_n_minus_one_squared_n_k1() {
    let n = n_k1();
    let nm1 = &n - 1u32;
    let one = BigUint::from(1u32);
    assert_eq!(run_mul_mod_n(&nm1, &nm1, &n), one);
}

#[test]
fn barrett_large_values_n_k1() {
    let n = n_k1();
    let a = BigUint::parse_bytes(
        b"DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA98765432100123456789ABCDEF",
        16,
    )
    .unwrap()
        % &n;
    let b = BigUint::parse_bytes(
        b"BAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00D",
        16,
    )
    .unwrap()
        % &n;
    let expected = (&a * &b) % &n;
    assert_eq!(run_mul_mod_n(&a, &b, &n), expected);
}

// ── Fermat inverse via Barrett ───────────────────────────────────────

fn build_test_module_inverse<'c>(context: &'c LlzkContext, n_limbs: [u64; LIMBS]) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    // The inverse body dispatches its inner multiplications through the
    // mul-mod-n helper. Emit the matching mul helper (k1 or r1) so the
    // module verifies as a self-contained unit.
    if n_limbs == SECP256K1_N {
        module
            .body()
            .append_operation(emit_secp256k1_mul_mod_n_helper(context).unwrap().into());
    } else if n_limbs == SECP256R1_N {
        module
            .body()
            .append_operation(emit_secp256r1_mul_mod_n_helper(context).unwrap().into());
    }

    let felt_ty = felt_type(context);
    let input_types = vec![felt_ty; LIMBS];
    let output_types = vec![felt_ty; LIMBS];
    let inputs = vec![(felt_ty, location); LIMBS];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, "test_inv_mod_n", function_type, &[], None)
        .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let a: [Value; LIMBS] = block_args::<LIMBS>(&block, 0).expect("block args");
    let result =
        append_inv_mod_n_barrett(&block, context, location, &a, &n_limbs).expect("inv_mod_n");
    block.append_operation(dialect::function::r#return(location, &result));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());
    module
}

fn run_inverse(a: &BigUint, n: &BigUint) -> BigUint {
    let n_limbs = limbs_from_big(n);
    let context = LlzkContext::new();
    let module = build_test_module_inverse(&context, n_limbs);
    assert!(module.as_operation().verify(), "module should verify");
    let args: Vec<InterpValue> = limbs_of(a).into_iter().collect();
    let mut interp = Interpreter::new(&module);
    let out = interp.run_function("@test_inv_mod_n", &args).expect("run");
    let mut acc = BigUint::from(0u32);
    for (i, v) in out.iter().enumerate() {
        let InterpValue::Felt(f) = v else {
            panic!("expected felt")
        };
        acc += f.as_biguint() << (64 * i);
    }
    acc
}

#[test]
fn barrett_inverse_three_n_k1() {
    let n = n_k1();
    let a = BigUint::from(3u32);
    let a_inv = run_inverse(&a, &n);
    assert_eq!((&a * &a_inv) % &n, BigUint::from(1u32));
}

#[test]
fn barrett_inverse_large_n_k1() {
    let n = n_k1();
    let a = BigUint::parse_bytes(
        b"0123456789ABCDEFFEDCBA9876543210BAADF00DDEADBEEFCAFEBABEDEADC0DE",
        16,
    )
    .unwrap()
        % &n;
    let a_inv = run_inverse(&a, &n);
    assert_eq!((&a * &a_inv) % &n, BigUint::from(1u32));
}

// ── Jacobian point operations ────────────────────────────────────────

/// secp256k1 generator G (affine coords).
fn generator_k1() -> (BigUint, BigUint) {
    (
        BigUint::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        )
        .unwrap(),
        BigUint::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        )
        .unwrap(),
    )
}

/// Known 2·G for secp256k1 in affine coords.
fn double_generator_k1() -> (BigUint, BigUint) {
    (
        BigUint::parse_bytes(
            b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            16,
        )
        .unwrap(),
        BigUint::parse_bytes(
            b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
            16,
        )
        .unwrap(),
    )
}

fn p_k1_big() -> BigUint {
    p_k1()
}

/// Mod-p inverse using num_bigint for the test side.
fn modinv(a: &BigUint, p: &BigUint) -> BigUint {
    // Fermat: a^(p-2) mod p.
    a.modpow(&(p - 2u32), p)
}

/// Converts a Jacobian point `(X, Y, Z)` to affine `(x, y)`. Panics if `Z = 0`.
fn jacobian_to_affine(x: &BigUint, y: &BigUint, z: &BigUint, p: &BigUint) -> (BigUint, BigUint) {
    assert!(z != &BigUint::from(0u32), "infinity");
    let z_inv = modinv(z, p);
    let z_inv_sq = (&z_inv * &z_inv) % p;
    let z_inv_cu = (&z_inv_sq * &z_inv) % p;
    let xa = (x * &z_inv_sq) % p;
    let ya = (y * &z_inv_cu) % p;
    (xa, ya)
}

fn build_test_module_jacobian_double<'c>(context: &'c LlzkContext) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    module.body().append_operation(
        emit_secp256k1_mul_mod_p_helper(context)
            .expect("mul_mod_p helper")
            .into(),
    );
    let felt_ty = felt_type(context);
    let input_types = vec![felt_ty; 3 * LIMBS];
    let output_types = vec![felt_ty; 3 * LIMBS];
    let inputs = vec![(felt_ty, location); 3 * LIMBS];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function =
        dialect::function::def(location, "test_point_double_k1", function_type, &[], None)
            .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let x: [Value; LIMBS] = block_args::<LIMBS>(&block, 0).expect("block args");
    let y: [Value; LIMBS] = block_args::<LIMBS>(&block, LIMBS).expect("block args");
    let z: [Value; LIMBS] = block_args::<LIMBS>(&block, 2 * LIMBS).expect("block args");
    let (xr, yr, zr) =
        Secp256k1::append_point_double(&block, context, location, &(x, y, z)).expect("double");
    let mut out = Vec::with_capacity(3 * LIMBS);
    out.extend(xr);
    out.extend(yr);
    out.extend(zr);
    block.append_operation(dialect::function::r#return(location, &out));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());
    module
}

fn run_point_double(x: &BigUint, y: &BigUint, z: &BigUint) -> (BigUint, BigUint, BigUint) {
    let context = LlzkContext::new();
    let module = build_test_module_jacobian_double(&context);
    assert!(module.as_operation().verify(), "module should verify");
    let mut args = Vec::with_capacity(3 * LIMBS);
    args.extend(limbs_of(x));
    args.extend(limbs_of(y));
    args.extend(limbs_of(z));
    let mut interp = Interpreter::new(&module);
    let out = interp
        .run_function("@test_point_double_k1", &args)
        .expect("run");
    let read = |slice: &[InterpValue]| -> BigUint {
        let mut acc = BigUint::from(0u32);
        for (i, v) in slice.iter().enumerate() {
            let InterpValue::Felt(f) = v else {
                panic!("expected felt")
            };
            acc += f.as_biguint() << (64 * i);
        }
        acc
    };
    (
        read(&out[0..LIMBS]),
        read(&out[LIMBS..2 * LIMBS]),
        read(&out[2 * LIMBS..]),
    )
}

#[test]
fn jacobian_double_g_matches_2g_k1() {
    let (gx, gy) = generator_k1();
    let one = BigUint::from(1u32);
    let (xr, yr, zr) = run_point_double(&gx, &gy, &one);
    let p = p_k1_big();
    let (xa, ya) = jacobian_to_affine(&xr, &yr, &zr, &p);
    let (g2x, g2y) = double_generator_k1();
    assert_eq!(xa, g2x);
    assert_eq!(ya, g2y);
}

/// Known 3·G for secp256k1 in affine.
fn triple_generator_k1() -> (BigUint, BigUint) {
    (
        BigUint::parse_bytes(
            b"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            16,
        )
        .unwrap(),
        BigUint::parse_bytes(
            b"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
            16,
        )
        .unwrap(),
    )
}

fn build_test_module_jacobian_mixed_add<'c>(context: &'c LlzkContext) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    module.body().append_operation(
        emit_secp256k1_mul_mod_p_helper(context)
            .expect("mul_mod_p helper")
            .into(),
    );
    let felt_ty = felt_type(context);
    // 3 Jacobian limbs + 2 affine limbs = 5 * LIMBS inputs.
    let input_types = vec![felt_ty; 5 * LIMBS];
    let output_types = vec![felt_ty; 3 * LIMBS];
    let inputs = vec![(felt_ty, location); 5 * LIMBS];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(
        location,
        "test_point_add_mixed_k1",
        function_type,
        &[],
        None,
    )
    .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let p1x: [Value; LIMBS] = block_args::<LIMBS>(&block, 0).expect("block args");
    let p1y: [Value; LIMBS] = block_args::<LIMBS>(&block, LIMBS).expect("block args");
    let p1z: [Value; LIMBS] = block_args::<LIMBS>(&block, 2 * LIMBS).expect("block args");
    let q_x: [Value; LIMBS] = block_args::<LIMBS>(&block, 3 * LIMBS).expect("block args");
    let q_y: [Value; LIMBS] = block_args::<LIMBS>(&block, 4 * LIMBS).expect("block args");
    let q_is_infinity = crate::blackboxes::ecdsa::limbs::append_felt_constant(
        &block,
        context,
        location,
        &acir::FieldElement::zero(),
    )
    .expect("zero");
    let (xr, yr, zr) = append_point_add_mixed_complete::<Secp256k1>(
        &block,
        context,
        location,
        &(p1x, p1y, p1z),
        &(q_x, q_y),
        q_is_infinity,
    )
    .expect("mixed add");
    let mut out = Vec::with_capacity(3 * LIMBS);
    out.extend(xr);
    out.extend(yr);
    out.extend(zr);
    block.append_operation(dialect::function::r#return(location, &out));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());
    module
}

fn run_point_add_mixed(
    p1: (&BigUint, &BigUint, &BigUint),
    q: (&BigUint, &BigUint),
) -> (BigUint, BigUint, BigUint) {
    let context = LlzkContext::new();
    let module = build_test_module_jacobian_mixed_add(&context);
    assert!(module.as_operation().verify(), "module should verify");
    let mut args = Vec::with_capacity(5 * LIMBS);
    args.extend(limbs_of(p1.0));
    args.extend(limbs_of(p1.1));
    args.extend(limbs_of(p1.2));
    args.extend(limbs_of(q.0));
    args.extend(limbs_of(q.1));
    let mut interp = Interpreter::new(&module);
    let out = interp
        .run_function("@test_point_add_mixed_k1", &args)
        .expect("run");
    let read = |slice: &[InterpValue]| -> BigUint {
        let mut acc = BigUint::from(0u32);
        for (i, v) in slice.iter().enumerate() {
            let InterpValue::Felt(f) = v else {
                panic!("expected felt")
            };
            acc += f.as_biguint() << (64 * i);
        }
        acc
    };
    (
        read(&out[0..LIMBS]),
        read(&out[LIMBS..2 * LIMBS]),
        read(&out[2 * LIMBS..]),
    )
}

#[test]
fn jacobian_2g_plus_g_matches_3g_k1() {
    let (gx, gy) = generator_k1();
    let (g2x, g2y) = double_generator_k1();
    let one = BigUint::from(1u32);
    // P1 = 2G in Jacobian with Z=1, Q = G in affine.
    let (xr, yr, zr) = run_point_add_mixed((&g2x, &g2y, &one), (&gx, &gy));
    let p = p_k1_big();
    let (xa, ya) = jacobian_to_affine(&xr, &yr, &zr, &p);
    let (g3x, g3y) = triple_generator_k1();
    assert_eq!(xa, g3x);
    assert_eq!(ya, g3y);
}

// ── Joint scalar mul (Shamir's trick) ────────────────────────────────

fn build_test_module_joint_scalar_mul<'c>(context: &'c LlzkContext) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    // Joint scalar mul calls mul-mod-p (per iteration) and inv-mod-p
    // (final jacobian-to-affine conversion). The inv body in turn calls
    // mul-mod-p, so we emit both helpers.
    module.body().append_operation(
        emit_secp256k1_mul_mod_p_helper(context)
            .expect("mul_mod_p helper")
            .into(),
    );
    module.body().append_operation(
        emit_secp256k1_inv_mod_p_helper(context)
            .expect("inv_mod_p helper")
            .into(),
    );
    let felt_ty = felt_type(context);
    // Inputs: G (8 limbs) + P (8 limbs) + G+P (8 limbs)
    // + G+P-is-infinity + u1 (4 limbs) + u2 (4 limbs) = 33 felts.
    let input_types = vec![felt_ty; 33];
    // Outputs: Rx (4) + Ry (4) + is_infinity (1) = 9 felts.
    let output_types = vec![felt_ty; 9];
    let inputs = vec![(felt_ty, location); 33];

    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(
        location,
        "test_joint_scalar_mul_k1",
        function_type,
        &[],
        None,
    )
    .expect("function.def");
    function.set_allow_witness_attr(true);
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let take = |offset: usize| -> [Value; LIMBS] {
        block_args::<LIMBS>(&block, offset).expect("block args")
    };
    let gx = take(0);
    let gy = take(4);
    let px = take(8);
    let py = take(12);
    let gpx = take(16);
    let gpy = take(20);
    let gp_is_inf: Value = block.argument(24).unwrap().into();
    let u1 = take(25);
    let u2 = take(29);

    let (rx, ry, is_inf) = append_joint_scalar_mul::<Secp256k1>(
        &block,
        context,
        location,
        &(gx, gy),
        &(px, py),
        &(gpx, gpy),
        gp_is_inf,
        &u1,
        &u2,
    )
    .expect("joint scalar mul");
    let mut out = Vec::with_capacity(9);
    out.extend(rx);
    out.extend(ry);
    out.push(is_inf);
    block.append_operation(dialect::function::r#return(location, &out));
    function.region(0).unwrap().append_block(block);
    module.body().append_operation(function.into());
    module
}

fn run_joint_scalar_mul(
    g: (&BigUint, &BigUint),
    p: (&BigUint, &BigUint),
    gp: (&BigUint, &BigUint),
    gp_is_inf: bool,
    u1: &BigUint,
    u2: &BigUint,
) -> (BigUint, BigUint, bool) {
    let context = LlzkContext::new();
    let module = build_test_module_joint_scalar_mul(&context);
    assert!(module.as_operation().verify(), "module should verify");
    let mut args = Vec::with_capacity(33);
    args.extend(limbs_of(g.0));
    args.extend(limbs_of(g.1));
    args.extend(limbs_of(p.0));
    args.extend(limbs_of(p.1));
    args.extend(limbs_of(gp.0));
    args.extend(limbs_of(gp.1));
    args.push(InterpValue::Felt(Felt::from_u64(u64::from(gp_is_inf))));
    args.extend(limbs_of(u1));
    args.extend(limbs_of(u2));
    let mut interp = Interpreter::new(&module);
    let out = interp
        .run_function("@test_joint_scalar_mul_k1", &args)
        .expect("run");
    let read = |slice: &[InterpValue]| -> BigUint {
        let mut acc = BigUint::from(0u32);
        for (i, v) in slice.iter().enumerate() {
            let InterpValue::Felt(f) = v else {
                panic!("expected felt")
            };
            acc += f.as_biguint() << (64 * i);
        }
        acc
    };
    let rx = read(&out[0..4]);
    let ry = read(&out[4..8]);
    let inf = match &out[8] {
        InterpValue::Felt(f) => f.as_biguint() == &BigUint::from(1u32),
        _ => panic!("expected felt"),
    };
    (rx, ry, inf)
}

#[test]
fn joint_scalar_mul_emits_loop_control_flow() {
    let context = LlzkContext::new();
    let module = build_test_module_joint_scalar_mul(&context);
    let mut while_count = 0;
    module.as_operation().walk(WalkOrder::PreOrder, |op| {
        if op.name().as_string_ref().as_str() == Ok("scf.while") {
            while_count += 1;
        }
        WalkResult::Advance
    });
    assert!(
        while_count > 0,
        "joint scalar mul should use LLZK loop control flow instead of unrolling every bit"
    );
}

#[test]
fn joint_scalar_mul_1g_plus_0p_equals_g_k1() {
    let (gx, gy) = generator_k1();
    let (px, py) = double_generator_k1(); // arbitrary non-G point
    let (gpx, gpy) = triple_generator_k1(); // G + P = G + 2G = 3G
    let u1 = BigUint::from(1u32);
    let u2 = BigUint::from(0u32);
    let (rx, ry, inf) = run_joint_scalar_mul((&gx, &gy), (&px, &py), (&gpx, &gpy), false, &u1, &u2);
    assert!(!inf);
    assert_eq!(rx, gx);
    assert_eq!(ry, gy);
}
