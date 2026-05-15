use libafl_cc::ToolWrapper;
use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses};
use std::env;
pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ warpper was called. Expected {:?} to end with c or cxx", dir),
        };

        dir.pop();

        // The sancov_ctx pass injects reads/writes to `__afl_prev_ctx`, a
        // u32 storage location provided by libafl_targets/src/coverage.c. With
        // `--libafl-no-link` (used during target configure / intermediate-tool
        // builds) libafl_targets is not linked, so the symbol is undefined and
        // the link fails. Provide a weak storage location via a compiled stub
        // that we generate on the fly and pass as an extra source file. When
        // `--libafl` links the final fuzzer binary, the strong definition in
        // libafl_targets wins over this weak one.
        let no_link = args.iter().any(|a| a == "--libafl-no-link");
        // `-c` means compile-only — passing an extra source file would break
        // the single-input → single-output invariant. Only add the stub for
        // link-producing invocations.
        let is_compile_only = args.iter().any(|a| a == "-c");
        let needs_stub = no_link && !is_compile_only;
        let stub_path = "/tmp/__afl_prev_ctx_stub.c";
        if needs_stub && !std::path::Path::new(stub_path).exists() {
            // Idempotent: same content every time, safe under parallel writes.
            // `visibility("default")` ensures the symbol stays exported even
            // when the target uses `-fvisibility=hidden` (lcms does), so DSOs
            // built against it can resolve their import.
            let _ = std::fs::write(
                stub_path,
                "__attribute__((weak, visibility(\"default\"))) unsigned int __afl_prev_ctx;\n",
            );
        }

        let mut cc = ClangWrapper::new();

        #[cfg(target_os = "linux")]
        cc.add_pass(LLVMPasses::AutoTokens);

        let cc_ref = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            // add arguments only if --libafl or --libafl-no-link are present
            .need_libafl_arg(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .link_staticlib(&dir, env!("CARGO_PKG_NAME"))
            .add_passes_linking_arg("-lm")
            .add_pass(LLVMPasses::Ctx)
            .add_arg("-fsanitize-coverage=trace-pc-guard");

        if needs_stub {
            cc_ref.add_arg(stub_path);
        }

        if let Some(code) = cc_ref.run().expect("Failed to run the wrapped compiler") {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
