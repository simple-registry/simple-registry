use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    thread,
};
use tokio::{runtime, sync::mpsc};
use tracing::info;

type TaskOutput = Result<(), Error>;
type BoxedTask = Pin<Box<dyn Future<Output = TaskOutput> + Send + 'static>>;

/// All errors that can occur in `TaskQueue` operations
#[derive(Debug)]
pub enum Error {
    RuntimeBuild(String),
    Mutex(String),
    Send(String),
    TaskExecution(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RuntimeBuild(e) => write!(f, "failed to build Tokio runtime: {e}"),
            Error::Mutex(e) => write!(f, "mutex error: {e}"),
            Error::Send(e) => write!(f, "failed to send task: {e}"),
            Error::TaskExecution(e) => write!(f, "task execution failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl<T> From<PoisonError<T>> for Error {
    fn from(e: PoisonError<T>) -> Self {
        Error::Mutex(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum TaskStatus {
    Queued,
    Running,
}

pub struct TaskQueue {
    sender: mpsc::UnboundedSender<(String, BoxedTask)>,
    statuses: Arc<Mutex<HashMap<String, TaskStatus>>>,
}

impl TaskQueue {
    pub fn new(worker_threads: usize) -> Result<Self, Error> {
        let (tx, mut rx) = mpsc::unbounded_channel::<(String, BoxedTask)>();
        let statuses = Arc::new(Mutex::new(HashMap::<String, TaskStatus>::new()));

        let rt = runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .map_err(|e| Error::RuntimeBuild(e.to_string()))?;

        let statuses_clone = Arc::clone(&statuses);

        thread::spawn(move || {
            rt.block_on(async move {
                while let Some((task_id, task)) = rx.recv().await {
                    let mut st = statuses_clone.lock().unwrap();
                    st.insert(task_id.clone(), TaskStatus::Running);
                    drop(st);

                    let statuses_inner = Arc::clone(&statuses_clone);
                    let id_clone = task_id.clone();

                    tokio::spawn(async move {
                        let _ = task.await;
                        let mut st = statuses_inner.lock().unwrap();
                        st.remove(&id_clone);
                    });
                }
            });
        });

        Ok(Self {
            sender: tx,
            statuses,
        })
    }

    pub fn submit<Fut>(&self, reference: &str, fut: Fut) -> Result<(), Error>
    where
        Fut: Future<Output = TaskOutput> + Send + 'static,
    {
        info!("Submitting task with reference `{}`", reference);
        let mut st = self.statuses.lock()?;
        if st.get(reference).is_some() {
            return Ok(());
        }
        st.insert(reference.to_string(), TaskStatus::Queued);
        drop(st);

        self.sender
            .send((reference.to_string(), Box::pin(fut)))
            .map_err(|e| Error::Send(e.to_string()))?;

        Ok(())
    }
}
