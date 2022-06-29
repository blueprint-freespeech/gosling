// std
use std::default::Default;
use std::vec::Vec;
use std::sync::*;
use std::sync::atomic::*;
use std::thread;
use std::thread::ThreadId;
use std::any::{Any, type_name};

// crates
use anyhow::{bail, ensure, Result};

struct Task {
    // closure
    closure: Box<dyn FnOnce() -> Box<dyn Any + Send> + Send + 'static>,
    // wait handle to notify
    wait_handle: Weak<Condvar>,
    // destination
    result: Weak<Mutex<Option<Box<dyn Any + Send>>>>,
}

pub struct TaskResult {
    wait_handle: Arc<Condvar>,
    result: Arc<Mutex<Option<Box<dyn Any + Send>>>>,
}

impl TaskResult {

    pub fn wait<T: Any>(&self) -> Result<T> {

        loop {
            // swap a None result with held result
            let mut local: Option<Box<dyn Any + Send>> = None;
            {
                let mut guard: MutexGuard<Option<Box<dyn Any + Send>>> = self.result.lock().unwrap();
                std::mem::swap::<Option<Box<dyn Any + Send>>>(&mut local, &mut guard);
            }
            // if some result was stored, attempt to cast and return
            if let Some(result) = local {
                // first try and cast to error type
                match result.downcast::<anyhow::Error>() {
                    Ok(err) => bail!(err),
                    // otherwise try the requested cast
                    Err(result) => match result.downcast::<T>() {
                        Ok(result) => return Ok(*result),
                        Err(_) => bail!("TaskResult::wait<T>(): could not cast result to type {}", type_name::<T>()),
                    }
                }
            }

            // suspend until notified
            if let Err(err) = self.wait_handle.wait(self.result.lock().unwrap()) {
                bail!("{}", err);
            }
        }
    }
}

#[derive(Clone)]
pub struct Worker {
    worker_id: usize,
    work_manager: Weak<WorkManager>,
}

impl Worker {
    pub fn new(worker_id: usize, work_manager: &Arc<WorkManager>) -> Result<Worker> {
        ensure!(work_manager.worker_count > worker_id, "Worker::new(): worker_id invalid for work_manager");
        Ok(Worker{worker_id: worker_id, work_manager: Arc::downgrade(work_manager)})
    }

    pub fn push<T: Send + 'static, F: FnOnce() -> Result<T> + Send + 'static>(&self, closure: F) -> Result<TaskResult> {
        if let Some(work_manager) = self.work_manager.upgrade() {
            return work_manager.push(self.worker_id, closure);
        }
        bail!("Worker::push(): parent WorkManager no longer valid");
    }

    pub fn thread_id(&self) -> Result<ThreadId> {
        let work_manager = self.work_manager.upgrade();
        if let Some(work_manager) = work_manager {
            return work_manager.thread_id(self.worker_id);
        }
        bail!("Worker::thread_id(): work_manager weak reference cannot be upgraded");
    }
}

// unsafe impl std::marker::Send for Worker {}

pub struct WorkManager {
    // numberof workers owned by this work manager
    worker_count: usize,

    // shared queues of tasks
    producer_queues: Vec<Arc<Mutex<Vec<Task>>>>,

    // worker thread handles
    threads: Mutex<Vec<thread::JoinHandle::<()>>>,

    // condition variables used to suspend worker threads when
    // they run out of work
    suspend_handles: Vec<Arc<Condvar>>,

    // set to true to indicate the worker threads need to finish up
    terminating: Arc<AtomicBool>,

    // the total number of pending tasks in the queues
    pending_tasks: Arc<AtomicUsize>,
}

impl WorkManager {
    pub fn new(worker_names: &[&str]) -> Result<Self> {
        ensure!(worker_names.len() > 0, "WorkManager::new(): worker_names must not be empty");

        // terminating signal is not set
        let terminating = Arc::new(AtomicBool::new(false));
        // start with no tasks
        let pending_tasks = Arc::new(AtomicUsize::new(0));


        let mut work_manager = WorkManager{
                worker_count: worker_names.len(),
                producer_queues: Default::default(),
                threads: Default::default(),
                suspend_handles: Default::default(),
                terminating: terminating,
                pending_tasks: pending_tasks,
            };

        // add and start our worker threads
        for worker_name in worker_names {
            work_manager.add_worker(worker_name)?;
        }
        Ok(work_manager)
    }

    fn add_worker(&mut self, worker_name: &str) -> Result<()> {

        let mut threads = self.threads.lock().unwrap();

        self.producer_queues.push(Default::default());
        self.suspend_handles.push(Default::default());

        // pass in the shared state as weak references
        let producer_queue = Arc::downgrade(self.producer_queues.last().unwrap());
        let suspend_handle = Arc::downgrade(self.suspend_handles.last().unwrap());
        let terminating = Arc::downgrade(&self.terminating);
        let pending_tasks = Arc::downgrade(&self.pending_tasks);

        let thread_handle = thread::Builder::new()
            .name(worker_name.to_string())
            .spawn(move || {
                Self::worker_func(producer_queue, suspend_handle, terminating, pending_tasks);
            })?;

        threads.push(thread_handle);
        Ok(())
    }

    fn accepting_tasks(&self) -> bool {
        // we may only accept new tasks if we are not terminating and
        // there are no pending tasks (the same conditions which signal
        // to the worker threads to exit their loop)
        if self.terminating.load(Ordering::Relaxed) &&
           self.pending_tasks.load(Ordering::Relaxed) == 0 {
            return false;
        }
        true
    }

    pub fn push<T: Send + 'static, F: FnOnce() -> Result<T> + Send + 'static>(&self, worker_id: usize, closure: F) -> Result<TaskResult> {

        // wrap the friendly closure into one which returns a Box'd result
        // that can store a dyn Any
        let closure = move || -> Box<dyn Any + Send> {
            match closure() {
                Ok(result) => Box::new(result),
                Err(err) => Box::new(err)
            }
        };
        self.push_impl(worker_id, closure)
    }

    fn push_impl<F: FnOnce() -> Box<dyn Any + Send> + Send + 'static>(&self, worker_id: usize, closure: F) -> Result<TaskResult> {

        if worker_id >= self.worker_count {
            bail!("WorkManager::push(): worker_id must be less than '{}'; received '{}'", self.worker_count, worker_id);
        } else if !self.accepting_tasks() {
            bail!("WorkManager::push(): WorkManager has joined and is no longer accepting tasks");
        }

        // update the total pending task counter first
        self.pending_tasks.fetch_add(1, Ordering::Relaxed);

        // add task to work queue
        let task_result = TaskResult{wait_handle: Default::default(), result: Default::default()};
        let task = Task{closure: Box::new(closure), wait_handle: Arc::downgrade(&task_result.wait_handle), result: Arc::downgrade(&task_result.result)};
        self.producer_queues[worker_id].lock().unwrap().push(task);

        // wake up worker thread
        self.suspend_handles[worker_id].notify_one();

        Ok(task_result)
    }

    pub fn thread_id(&self, worker_id: usize) -> Result<ThreadId> {

        if worker_id >= self.worker_count {
            bail!("WorkManager::push(): worker_id must be less than '{}'; received '{}'", self.worker_count, worker_id);
        }

        match self.threads.lock() {
            Ok(threads) => Ok(threads[worker_id].thread().id()),
            Err(_) => bail!("WorkManager::thread_id(): cannot lock threads mutex"),
        }
    }

    pub fn join(&self) -> Result<()> {

        // signals to threads that they may now terminate
        ensure!(!self.terminating.swap(true, Ordering::Relaxed), "WorkManager::join(): already joined");

        // wake up all the worker threads in case they are sleeping
        for suspend_handle in &self.suspend_handles {
            suspend_handle.notify_one();
        }

        // wait for each thread to join
        let mut threads = self.threads.lock().unwrap();
        while let Some(handle) = threads.pop() {
            if let Err(err) = handle.join() {
                std::panic::resume_unwind(err);
            }
        }

        Ok(())
    }

    fn worker_func(producer_queue_weak: Weak<Mutex<Vec<Task>>>, suspend_handle_weak: Weak<Condvar>, terminating_weak: Weak<AtomicBool>, pending_tasks_weak: Weak<AtomicUsize>) {
        let mut consumer_queue = Vec::<Task>::new();

        let finished = || -> bool {
            if !terminating_weak.upgrade().unwrap().load(Ordering::Relaxed) {
                return false;
            } else if pending_tasks_weak.upgrade().unwrap().load(Ordering::Relaxed) > 0 {
                return false;
            }
            true
        };

        // spin until WorkManager has no more tasks
        while !finished() {
            let queue_len = consumer_queue.len();
            // run all our pending tasks
            for task in consumer_queue.drain(..) {
                let closure_result = (task.closure)();
                let task_wait_handle = task.wait_handle.upgrade();
                let task_result = task.result.upgrade();

                // we only need to store the result if
                // the caller has saved off the TaskResult
                if let (Some(twait_handle), Some(tresult)) = (task_wait_handle, task_result) {
                    // box the closure result
                    let mut retval = Some(closure_result);
                    // swap in the result
                    std::mem::swap::<Option<Box<dyn Any + Send>>>(
                        &mut retval,
                        &mut tresult.lock().unwrap());

                    // notify the task result
                    twait_handle.notify_one();
                }
            }

            // update pending_tasks counter
            pending_tasks_weak.upgrade().unwrap().fetch_sub(queue_len, Ordering::Relaxed);

            // finally swap out queues to get new tasks
            let producer_queue = producer_queue_weak.upgrade().unwrap();
            let mut producer_queue = producer_queue.lock().unwrap();

            // suspend thread if producer queue is empty and we are not
            // terminating
            if producer_queue.len() == 0 {
                let suspend_handle = suspend_handle_weak.upgrade().unwrap();
                let terminating = terminating_weak.upgrade().unwrap();
                // TODO: Note that this code is a little problematic, since
                // we get the lock and immediately drop it. Consider
                // replacing this whole implementation with crossbeam. (#27.)
                if terminating.load(Ordering::Relaxed) {
                    // suspend for a 16ms rather than busy looping
                    let _ignore = suspend_handle.wait_timeout(producer_queue, std::time::Duration::from_millis(16)).unwrap();
                } else {
                    let _ignore = suspend_handle.wait(producer_queue).unwrap();
                }
            } else {
                // otherwise swap the queues and run the tasks
                std::mem::swap::<Vec<Task>>(&mut consumer_queue, &mut producer_queue);
            }
        }
    }
}

impl Drop for WorkManager {
    fn drop(&mut self) {
        // we can ignore duplicate join
        let _ = self.join();
    }
}

#[test]
fn test_work_manager() -> Result<()> {

    const WORKER_NAMES: [&str; 3] = ["worker1", "worker2", "worker3"];
    const WORKER_COUNT: usize = WORKER_NAMES.len();
    let work_manager: Arc<WorkManager> = Arc::<WorkManager>::new(WorkManager::new(&WORKER_NAMES)?);

    let worker_0 = Worker::new(0, &work_manager)?;

    // task should retur 41
    let task_result = worker_0.push(|| {
        println!("Worker 0: sleeping for 5 seconds");
        thread::sleep(std::time::Duration::from_secs(5));
        return Ok(42u8);
    })?;
    ensure!(task_result.wait::<u8>()? == 42u8);

    // task should return a string
    let task_result = worker_0.push(|| {
        println!("Worker 0: building a string");
        return Ok(String::from("Hello There"));
    })?;
    ensure!(task_result.wait::<String>()? == "Hello There");

    // this task should return a failure
    let task_result = worker_0.push(|| -> Result<()> {
        bail!("An error!");
    })?;
    match task_result.wait::<()>() {
        Err(err) => ensure!(err.to_string() == "An error!"),
        Ok(_) => bail!("Expected task to return an error"),
    }

    let counter = Arc::new(AtomicUsize::new(0));

    for i in 0..WORKER_COUNT {
        let worker = Worker::new(i, &work_manager)?;
        let worker_0 = worker_0.clone();
        let counter = counter.clone();
        worker.push(
            move || {
                println!("Worker {}: hello!", i);
                let counter = counter.clone();
                worker_0.push(move || {
                    println!("Worker 0: hello from nested task from Worker {}", i);
                    counter.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                })?;
                return Ok(());
            })?;
    }

    match work_manager.push(WORKER_COUNT, || Ok(())) {
        Ok(_) => bail!("Expected work_manager.push({},...) to fail", WORKER_COUNT),
        _ => ()
    };

    work_manager.join()?;
    match work_manager.join() {
        Ok(()) => bail!("Expected work_manager.join() to return error on second join"),
        _ => ()
    };

    ensure!(counter.load(Ordering::Relaxed) == WORKER_COUNT, "Expecter counter to equal {}", WORKER_COUNT);

    Ok(())
}
