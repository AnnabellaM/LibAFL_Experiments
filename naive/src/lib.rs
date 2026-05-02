//! A singlethreaded libfuzzer-like fuzzer that can auto-restart.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
use libafl::observers::CanTrack;
use libafl::HasMetadata;
use libafl_bolts::{
    current_nanos,
    impl_serdeany,
    os::dup2,
    rands::{Rand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge, NamedTuple},
    AsSlice, Named,
};

use clap::{Arg, Command};
use core::{num::NonZeroUsize, time::Duration};
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
    corpus::{Corpus, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, StateInitializer, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations::havoc_mutations, tokens_mutations, LogMutationMetadata,
        MutationResult, Mutator, MutatorsTuple, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasExecutions, HasRand, HasStartTime, StdState},
    Error,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use libafl_targets::autotokens;

// ---------------------------------------------------------------------------
// Lineage tracking
// ---------------------------------------------------------------------------

/// State metadata that holds the mutation names applied during the current
/// mutation. Written by [`LineageMutator`] in `mutate()` and consumed by
/// [`LineageFeedback`] in `append_metadata()` — which is called *before*
/// `corpus.add()` writes the `.metadata` file to disk.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MutationLog {
    pub names: Vec<Cow<'static, str>>,
    /// Total executions at the time `mutate()` was called.
    pub execs: u64,
    /// Milliseconds since fuzzing started at the time `mutate()` was called.
    pub elapsed_ms: u64,
}
impl_serdeany!(MutationLog);

/// Testcase metadata written by [`LineageFeedback`] before the entry is saved
/// to disk. Mirrors AFL++'s `src:NNNNNN,time:TTTTTT,execs:EEEEEE` encoding.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ParentInfo {
    /// Raw [`CorpusId`] integer of the parent (None for seeds / initial inputs).
    pub parent_id: Option<u64>,
    /// Filename of the parent as stored on disk (if available).
    pub parent_file: Option<String>,
    /// Total executions when this entry was discovered.
    pub execs: u64,
    /// Milliseconds of fuzzing elapsed when this entry was discovered.
    pub elapsed_ms: u64,
}
impl_serdeany!(ParentInfo);

/// A mutator that applies random stacked mutations (like [`StdScheduledMutator`])
/// and records the name of each applied mutation into [`MutationLog`] in state.
pub struct LineageMutator<MT> {
    name: Cow<'static, str>,
    mutations: MT,
    max_stack_pow: NonZeroUsize,
}

impl<MT: NamedTuple> LineageMutator<MT> {
    pub fn new(mutations: MT) -> Self {
        Self {
            name: Cow::from(format!("LineageMutator[{}]", mutations.names().join(", "))),
            mutations,
            max_stack_pow: NonZeroUsize::new(7).unwrap(),
        }
    }
}

impl<MT> Named for LineageMutator<MT> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S, MT> Mutator<I, S> for LineageMutator<MT>
where
    S: HasRand + HasMetadata + HasExecutions + HasStartTime,
    MT: MutatorsTuple<I, S> + NamedTuple,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        // Snapshot execs and elapsed time at the start of this mutation round
        let execs = *state.executions();
        let elapsed_ms = (libafl_bolts::current_time() - *state.start_time()).as_millis() as u64;

        // Initialise or clear the log for this mutation round
        if state.metadata_map().contains::<MutationLog>() {
            let log = state.metadata_map_mut().get_mut::<MutationLog>().unwrap();
            log.names.clear();
            log.execs = execs;
            log.elapsed_ms = elapsed_ms;
        } else {
            state.add_metadata(MutationLog { names: vec![], execs, elapsed_ms });
        }

        // Pick a random number of mutations: 1 .. 2^max_stack_pow (mirrors StdScheduledMutator)
        let num = 1 + state.rand_mut().below(self.max_stack_pow);
        // Safety: mutations tuple is non-empty (compile-time guarantee from havoc_mutations)
        let mutations_len = NonZeroUsize::new(self.mutations.len()).expect("mutations must be non-empty");
        let mut result = MutationResult::Skipped;

        for _ in 0..num {
            let idx = state.rand_mut().below(mutations_len);
            let outcome = self.mutations.get_and_mutate(idx.into(), state, input)?;
            if outcome == MutationResult::Mutated {
                result = MutationResult::Mutated;
                if let Some(name) = self.mutations.name(idx as usize) {
                    state
                        .metadata_map_mut()
                        .get_mut::<MutationLog>()
                        .unwrap()
                        .names
                        .push(name.clone());
                }
            }
        }
        Ok(result)
    }
}

/// A feedback that attaches [`LogMutationMetadata`] to a testcase **before**
/// it is saved to disk. Always returns `false` from `is_interesting` so it
/// never influences the interesting decision on its own.
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
    S: HasMetadata + HasCurrentCorpusId + HasCorpus,
{
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error> {
        // Attach mutation names
        if let Some(log) = state.metadata_map().get::<MutationLog>() {
            if !log.names.is_empty() {
                testcase.add_metadata(LogMutationMetadata::new(log.names.clone()));
            }
        }

        // Only attach ParentInfo for fuzz-generated entries (not seeds).
        // During load_initial_inputs no corpus entry is being fuzzed, so
        // current_corpus_id() returns None — we use that as the sentinel.
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
                .unwrap_or_default();

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

    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let mut feedback = feedback_or!(
        map_feedback,
        TimeFeedback::new(&time_observer),
        LineageFeedback::new()  // attaches mutation names before corpus.add writes to disk
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

    let mutator = StdMutationalStage::new(LineageMutator::new(
        havoc_mutations().merge(tokens_mutations()),
    ));

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe { libfuzzer_test_one_input(buf) };
        ExitKind::Ok
    };

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let mut stages = tuple_list!(mutator);

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
