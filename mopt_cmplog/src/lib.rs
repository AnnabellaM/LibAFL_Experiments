//! A singlethreaded libfuzzer-like fuzzer that can auto-restart.
//!
//! Combines the MOpt mutator (adaptive operator selection) with the
//! cmplog/i2s tracing+input2state stages. Lineage tracking semantics
//! follow the `mopt` crate: per-mutation names are not captured because
//! `StdMOptMutator`'s internal stacking is private; only `ParentInfo`
//! (parent_id, parent_file, execs, elapsed_ms) is recorded.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
use libafl::observers::CanTrack;
use libafl::HasMetadata;

use libafl_bolts::{
    current_nanos,
    impl_serdeany,
    os::dup2,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice, Named,
};

use clap::{Arg, Command};
use core::time::Duration;
#[cfg(unix)]
use nix::{self, unistd::dup};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    borrow::Cow,
    env,
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
    process,
};

use libafl::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, StateInitializer, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations::havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations,
        MutationResult, Mutator, StdMOptMutator, StdScheduledMutator, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{StdMutationalStage, TracingStage},
    state::{HasCorpus, HasExecutions, HasStartTime, StdState},
    Error,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use libafl_targets::autotokens;

// ---------------------------------------------------------------------------
// Lineage tracking
//
// MOpt does its own internal stacking via private `core_mutate`/`pilot_mutate`,
// so we cannot intercept individual mutation names without forking the MOpt
// source. We snapshot execs / elapsed_ms via a thin wrapper around the inner
// mutator, and attach `ParentInfo` (parent_id, parent_file, execs, elapsed_ms)
// in the `LineageFeedback`. The per-mutation name list is left empty.
// ---------------------------------------------------------------------------

/// State metadata holding execs and elapsed_ms snapshotted at the start of
/// each `mutate()` call. Names list is intentionally empty for MOpt — see
/// the module-level note.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MutationLog {
    pub names: Vec<Cow<'static, str>>,
    pub execs: u64,
    pub elapsed_ms: u64,
}
impl_serdeany!(MutationLog);

/// Testcase metadata written by [`LineageFeedback`] before the entry is saved
/// to disk. Mirrors AFL++'s `src:NNNNNN,time:TTTTTT,execs:EEEEEE` encoding.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ParentInfo {
    pub parent_id: Option<u64>,
    pub parent_file: Option<String>,
    pub execs: u64,
    pub elapsed_ms: u64,
}
impl_serdeany!(ParentInfo);

/// Wraps any `Mutator` to snapshot execs/elapsed_ms into [`MutationLog`] at
/// the start of each `mutate()` call, then delegates to the inner mutator.
/// Used for MOpt where we cannot intercept individual mutation names.
pub struct LineageMutatorWrap<M> {
    name: Cow<'static, str>,
    inner: M,
}

impl<M: Named> LineageMutatorWrap<M> {
    pub fn new(inner: M) -> Self {
        Self {
            name: Cow::from(format!("LineageMutatorWrap[{}]", inner.name())),
            inner,
        }
    }
}

impl<M> Named for LineageMutatorWrap<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S, M> Mutator<I, S> for LineageMutatorWrap<M>
where
    S: HasMetadata + HasExecutions + HasStartTime,
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let execs = *state.executions();
        let elapsed_ms = (libafl_bolts::current_time() - *state.start_time()).as_millis() as u64;

        if state.metadata_map().contains::<MutationLog>() {
            let log = state.metadata_map_mut().get_mut::<MutationLog>().unwrap();
            log.names.clear();
            log.execs = execs;
            log.elapsed_ms = elapsed_ms;
        } else {
            state.add_metadata(MutationLog { names: vec![], execs, elapsed_ms });
        }

        self.inner.mutate(state, input)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// A feedback that attaches [`ParentInfo`] to a testcase **before** it is
/// saved to disk. Always returns `false` from `is_interesting`.
pub struct LineageFeedback {
    name: Cow<'static, str>,
}

impl LineageFeedback {
    pub fn new() -> Self {
        Self { name: "LineageFeedback".into() }
    }
}

impl Named for LineageFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for LineageFeedback {}

impl<EM, OT, S> Feedback<EM, BytesInput, OT, S> for LineageFeedback
where
    S: HasMetadata + HasCurrentCorpusId + HasCorpus + HasExecutions + HasStartTime,
{
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error> {
        if let Some(parent_id) = state.current_corpus_id().ok().flatten() {
            let parent_file = state
                .corpus()
                .get(parent_id)
                .ok()
                .and_then(|tc| tc.borrow().filename().clone());

            // i2s stage uses StdScheduledMutator (not LineageMutatorWrap), so it
            // does not refresh MutationLog. Fall back to live state values when
            // the snapshot is missing or stale enough that the feedback is firing
            // outside a MOpt mutate() round.
            let (execs, elapsed_ms) = state
                .metadata_map()
                .get::<MutationLog>()
                .map(|log| (log.execs, log.elapsed_ms))
                .unwrap_or_else(|| {
                    let execs = *state.executions();
                    let elapsed_ms =
                        (libafl_bolts::current_time() - *state.start_time()).as_millis() as u64;
                    (execs, elapsed_ms)
                });

            testcase.add_metadata(ParentInfo {
                parent_id: Some(usize::from(parent_id) as u64),
                parent_file,
                execs,
                elapsed_ms,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    if let Some(filenames) = res.get_many::<String>("remaining") {
        let filenames: Vec<&str> = filenames.map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(out_dir, crashes, in_dir, tokens, timeout).expect("An error occurred while fuzzing");
}

fn run_testcases(filenames: &[&str]) {
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {}", fname);

        let mut file = File::open(fname).expect("No file found");
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Buffer overflow");

        unsafe { libfuzzer_test_one_input(&buffer) };
    }
}

/// The actual fuzzer
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: PathBuf,
    tokenfile: Option<PathBuf>,
    timeout: Duration,
) -> Result<(), Error> {
    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
        LineageFeedback::new()
    );

    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            OnDiskCorpus::new(objective_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    println!("Let's fuzz :)");

    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // MOpt mutator wrapped to snapshot execs/elapsed_ms for lineage
    let mutator = StdMutationalStage::new(LineageMutatorWrap::new(
        StdMOptMutator::new::<BytesInput, _>(
            &mut state,
            havoc_mutations().merge(tokens_mutations()),
            7,
            5,
        )?,
    ));

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe { libfuzzer_test_one_input(buf) };
        ExitKind::Ok
    };

    let mut tracing_harness = harness;

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // Setup a tracing stage in which we log comparisons
    let tracing = TracingStage::new(InProcessExecutor::with_timeout(
        &mut tracing_harness,
        tuple_list!(cmplog_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        // Give it more time!
        timeout * 10,
    )?);

    // The order of the stages matter!
    let mut stages = tuple_list!(tracing, i2s, mutator);

    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(target_os = "linux")]
        {
            toks += autotokens()?;
        }

        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
