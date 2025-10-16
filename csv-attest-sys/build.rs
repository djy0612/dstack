use std::env;
use std::path::Path;

fn main() {
    // 告诉 cargo 如果这些文件改变了，重新运行构建脚本
    println!("cargo:rerun-if-changed=sdk/csv_sdk.h");
    println!("cargo:rerun-if-changed=sdk/csv_status.h");
    
    // 设置链接库和路径
    let current_dir = env::current_dir().unwrap();
    let sdk_dir = current_dir.join("sdk");
    
    // 检查静态库是否存在
    let lib_path = sdk_dir.join("libcsv.a");
    if !lib_path.exists() {
        panic!("Static library not found: {}", lib_path.display());
    }
    
    // 链接官方 CSV SDK（使用本地拷贝的静态库）
    println!("cargo:rustc-link-lib=static=csv");
    println!("cargo:rustc-link-search=native={}", sdk_dir.display());
    
    // 链接 GMSSL 库
    if Path::new("/opt/gmssl/lib").exists() {
        println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }
    
    // 链接系统库
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
    
    // 生成 bindgen 绑定
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("bindings.rs");
    
    // 检查文件是否存在
    let csv_sdk_header = sdk_dir.join("csv_sdk.h");
    let csv_status_header = sdk_dir.join("csv_status.h");
    
    if !csv_sdk_header.exists() {
        panic!("CSV SDK header not found: {}", csv_sdk_header.display());
    }
    if !csv_status_header.exists() {
        panic!("CSV status header not found: {}", csv_status_header.display());
    }
    
    // 设置 bindgen 参数
    let mut bindgen_builder = bindgen::Builder::default()
        .header(csv_sdk_header.to_string_lossy())
        .header(csv_status_header.to_string_lossy())
        .clang_arg("-I/opt/gmssl/include")
        .clang_arg(&format!("-I{}", sdk_dir.display()))
        .allowlist_function("ioctl_get_attestation_report")
        .allowlist_function("vmmcall_get_attestation_report")
        .allowlist_function("verify_attestation_report")
        .allowlist_function("ioctl_get_sealing_key")
        .allowlist_function("vmmcall_get_sealing_key")
        .allowlist_type("csv_attestation_report")
        .allowlist_type("csv_attestation_user_data")
        .allowlist_type("csv_guest_mem")
        .allowlist_type("hash_block_u")
        .allowlist_type("hash_block_t")
        .allowlist_type("chip_key_id_t")
        .allowlist_type("userid_u")
        .allowlist_type("ecc_pubkey_t")
        .allowlist_type("ecc_signature_t")
        .allowlist_type("chip_root_cert_t")
        .allowlist_type("csv_cert_t")
        .allowlist_var("GUEST_ATTESTATION_NONCE_SIZE")
        .allowlist_var("GUEST_ATTESTATION_DATA_SIZE")
        .allowlist_var("HASH_LEN")
        .allowlist_var("USER_DATA_SIZE")
        .allowlist_var("HASH_BLOCK_LEN")
        .allowlist_var("SN_LEN")
        .allowlist_var("VM_ID_SIZE")
        .allowlist_var("VM_VERSION_SIZE")
        .allowlist_var("ECC_LEN")
        .allowlist_var("ECC_POINT_SIZE")
        .allowlist_var("SIZE_INT32")
        .allowlist_var("ATTESTATION_REPORT_SIGNED_SIZE")
        .allowlist_var("KEY_USAGE_TYPE_HRK")
        .allowlist_var("KEY_USAGE_TYPE_HSK")
        .allowlist_var("KEY_USAGE_TYPE_OCA")
        .allowlist_var("KEY_USAGE_TYPE_PEK")
        .allowlist_var("KEY_USAGE_TYPE_CEK")
        .allowlist_var("KEY_USAGE_TYPE_INVALID")
        .allowlist_var("CURVE_ID_TYPE_P256")
        .allowlist_var("CURVE_ID_TYPE_P384")
        .allowlist_var("CURVE_ID_TYPE_SM2_256")
        .allowlist_var("CSV_SUCCESS")
        .allowlist_var("CSV_ERROR_INVALID_PARAM")
        .allowlist_var("CSV_ERROR_MEMORY_ALLOC")
        .allowlist_var("CSV_ERROR_IOCTL_FAILED")
        .allowlist_var("CSV_ERROR_HYPERCALL_FAILED")
        .allowlist_var("CSV_ERROR_VERIFICATION_FAILED")
        .allowlist_var("CSV_ERROR_CERT_CHAIN_FAILED");
    
    // 添加系统头文件路径
    if let Ok(sysroot) = env::var("RECIPE_SYSROOT_NATIVE") {
        let include_path = format!("{}/usr/include", sysroot);
        if Path::new(&include_path).exists() {
            bindgen_builder = bindgen_builder.clang_arg(format!("-I{}", include_path));
        }
    }
    
    // 生成绑定
    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings");
    
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}