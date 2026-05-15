//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
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
    tuples::tuple_list,
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
    io::{self, Write},
    path::PathBuf,
};

use libafl::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, StateInitializer, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, scheduled::StdScheduledMutator, GrimoireExtensionMutator,
        GrimoireRandomDeleteMutator, GrimoireRecursiveReplacementMutator,
        GrimoireStringReplacementMutator, I2SRandReplace, MutationResult, Mutator, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{mutational::StdMutationalStage, GeneralizationStage, TracingStage},
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
// Grimoire has three mutator stages (i2s, havoc, grimoire), and the grimoire
// stage operates on `GeneralizedInput` via `StdMutationalStage::transforming`.
// We use the mopt-style approach: a thin `LineageMutatorWrap<M>` snapshots
// execs/elapsed_ms before delegating to the inner mutator (works generically
// for both BytesInput and GeneralizedInput stages), and `LineageFeedback`
// attaches `ParentInfo` to the saved `BytesInput` testcase. Per-mutation
// names are not captured — the Grimoire mutator tuple operates on the
// transformed input type and the existing LineageMutator pattern would need
// extra type juggling for marginal benefit.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MutationLog {
    pub names: Vec<Cow<'static, str>>,
    pub execs: u64,
    pub elapsed_ms: u64,
}
impl_serdeany!(MutationLog);

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

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

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
                .default_value("12000"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir\n{:?}",
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

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
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

    fuzz(in_dir, out_dir, crashes, tokens, timeout).expect("An error occurred while fuzzing");
}

fn run_testcases(filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
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

        let input = BytesInput::from_file(fname).expect("no file found");

        let target_bytes = input.target_bytes();
        let mut bytes = target_bytes.as_slice().to_vec();
        if *bytes.last().unwrap() != 0 {
            bytes.push(0);
        }
        unsafe {
            println!("Testcase: {}", std::str::from_utf8_unchecked(&bytes));
        }
        unsafe { libfuzzer_test_one_input(&bytes) };
    }
}

/// The actual fuzzer
fn fuzz(
    in_dir: PathBuf,
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
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

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
    });

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
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

    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") })
        .track_indices()
        .track_novelties();

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer),
        LineageFeedback::new()
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    // Read tokens
    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = &tokenfile {
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

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let generalization = GeneralizationStage::new(&edges_observer);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        /*use libafl::inputs::generalized::GeneralizedItem;
        if input.grimoire_mutated {
            if let Some(gen) = input.generalized() {
                print!(">> ");
                for e in gen {
                    match e {
                        GeneralizedItem::Bytes(b) => print!("`{}`", unsafe { std::str::from_utf8_unchecked(&b) }),
                        GeneralizedItem::Gap => print!(" <GAP> "),
                    }
                }
                print!("\n");
            }
            let bytes = input.generalized_to_bytes();
            println!("@@ {}", unsafe { std::str::from_utf8_unchecked(&bytes) });
        }*/
        let target_bytes = input.target_bytes();
        let bytes = target_bytes.as_slice();
        unsafe { libfuzzer_test_one_input(&bytes) };
        ExitKind::Ok
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let mut tracing_harness = |input: &BytesInput| {
        let target_bytes = input.target_bytes();
        let bytes = target_bytes.as_slice();
        unsafe { libfuzzer_test_one_input(&bytes) };
        ExitKind::Ok
    };

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

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[in_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &in_dir);
                std::process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    let i2s = StdMutationalStage::new(LineageMutatorWrap::new(
        StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())),
    ));

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations(), 2).unwrap();
    let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrimoireExtensionMutator::new(),
            GrimoireRecursiveReplacementMutator::new(),
            GrimoireStringReplacementMutator::new(),
            // give more probability to avoid large inputs
            GrimoireRandomDeleteMutator::new(),
            GrimoireRandomDeleteMutator::new(),
        ),
        3,
    )
    .unwrap();

    let mut stages = tuple_list!(
        generalization,
        tracing,
        i2s,
        StdMutationalStage::new(LineageMutatorWrap::new(mutator)),
        StdMutationalStage::transforming(LineageMutatorWrap::new(grimoire_mutator))
    );

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
